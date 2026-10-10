"""Redact credential-bearing URL parts and HTTP auth tokens from report text."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_URL_PATTERN = re.compile(r"""https?://[^\s"'<>]+""", re.IGNORECASE)
_AUTH_PATTERN = re.compile(r"""(?i)\b(Bearer|Basic)\s+([^\s,;"']+)""")
_SENSITIVE_QUERY_KEY = re.compile(
    r"(?i)(token|secret|password|passwd|api[-_]?key|credential|authorization|signature|"
    r"(^|[_-])auth($|[_-])|(^|[_-])key($|[_-]))"
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"

_SENSITIVE_FIELD_EXACT = {
    "auth", "authorization", "key", "secret", "token", "password", "passwd",
    "credential", "credentials", "cookie", "setcookie", "clientsecret",
    "apikey", "accesskey", "accesskeyid", "privatekey", "secretaccesskey",
    "accesstoken", "refreshtoken", "idtoken", "sessionid", "sessiontoken",
}
_SENSITIVE_FIELD_SUFFIXES = (
    "authorization", "accesstoken", "refreshtoken", "idtoken", "sessiontoken",
    "token", "clientsecret", "secretaccesskey", "secret", "password", "passwd",
    "credentials", "credential", "apikey", "accesskeyid", "accesskey",
    "privatekey", "cookie", "setcookie",
)
_PLACEHOLDER_VALUES = {
    "changeme", "example", "placeholder", "todo", "none", "null", "undefined",
    "redacted", "your-token", "your_api_key", "your-api-key", "replace_me",
    "replace-with-token",
}


def _redact_params(value: str) -> str:
    if not value or "=" not in value:
        return value
    params = parse_qsl(value, keep_blank_values=True)
    if not params:
        return value
    return urlencode(
        [
            (key, "[REDACTED]" if _SENSITIVE_QUERY_KEY.search(key) else item)
            for key, item in params
        ],
        doseq=True,
    )


def _redact_url_match(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    suffix = ""
    while raw_url and raw_url[-1] in _TRAILING_URL_PUNCTUATION:
        suffix = raw_url[-1] + suffix
        raw_url = raw_url[:-1]

    try:
        parts = urlsplit(raw_url)
        if not parts.scheme or not parts.netloc:
            return raw_url + suffix
    except ValueError:
        # Prefer dropping a malformed URL from evidence over risking a
        # credential leak through unusual userinfo or bracket syntax.
        return "[REDACTED_URL]" + suffix

    netloc = parts.netloc
    if "@" in netloc:
        # Strip both username and password, retain only the actual host.
        netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]

    query = _redact_params(parts.query)
    fragment = _redact_params(parts.fragment)
    safe_url = urlunsplit((parts.scheme, netloc, parts.path, query, fragment))
    return safe_url + suffix


def redact_sensitive_text(value: str | None) -> str | None:
    """Redact URL userinfo, sensitive URL parameters and Bearer/Basic tokens."""
    if not isinstance(value, str) or not value:
        return value
    value = _URL_PATTERN.sub(_redact_url_match, value)
    value = _AUTH_PATTERN.sub(r"\1 [REDACTED]", value)
    return value


def _is_sensitive_field_name(key: str) -> bool:
    """Recognize credential field names without substring matches like 'tokenizer'."""
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if normalized in _SENSITIVE_FIELD_EXACT:
        return True
    if normalized.endswith(_SENSITIVE_FIELD_SUFFIXES):
        return True
    # Treat separator-delimited KEY suffixes as credential fields, without
    # matching unrelated words such as "monkey".
    return bool(re.search(r"(?i)(?:^|[_-])key$", key))


def _is_placeholder_or_reference(value: str) -> bool:
    candidate = value.strip().strip("\\\"'").strip().lower()
    if not candidate or candidate.startswith("$") or "${" in candidate:
        return True
    if candidate in _PLACEHOLDER_VALUES:
        return True
    return candidate.startswith(("your_", "your-", "replace_", "replace-"))


def redact_sensitive_value(value, *, field_name: str | None = None):
    """Recursively redact metadata, using sensitive field names as context.

    Values under fields such as api_key, authorization, password, or token are
    redacted even when they are short and do not include a URL/auth prefix.
    Obvious placeholders and runtime references remain useful and are safe to
    show. Dictionary keys are sanitized too because they can be user-controlled.
    """
    if isinstance(value, str):
        if field_name and _is_sensitive_field_name(field_name):
            if not _is_placeholder_or_reference(value):
                return "[REDACTED]"
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_sensitive_value(item, field_name=field_name) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_value(item, field_name=field_name) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(key, str):
                safe_key = redact_sensitive_text(key) or ""
                result[safe_key] = redact_sensitive_value(item, field_name=key)
            else:
                result[key] = redact_sensitive_value(item)
        return result
    return value
