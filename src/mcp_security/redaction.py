"""Redact credential-bearing URL parts and HTTP auth tokens from report text."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_URL_PATTERN = re.compile(r"https?://[^\\s\\\"'<>]+", re.IGNORECASE)
_AUTH_PATTERN = re.compile(r"(?i)\\b(Bearer|Basic)\\s+([^\\s,;\\\"']+)")
_SENSITIVE_QUERY_KEY = re.compile(
    r"(?i)(token|secret|password|passwd|api[-_]?key|credential|authorization|signature|"
    r"(^|[_-])auth($|[_-])|(^|[_-])key($|[_-]))"
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


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
    value = _AUTH_PATTERN.sub(r"\\1 [REDACTED]", value)
    return value


def redact_sensitive_value(value):
    """Recursively redact strings in a finding's JSON-compatible metadata."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_sensitive_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_sensitive_value(item) for key, item in value.items()}
    return value
