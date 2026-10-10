"""Heuristics for hardcoded secret-like literal values in configuration.

This is separate from capability-based secret *access* detection (which
looks at env var names, see analyzers.capabilities). This module instead
flags values that look like an actual secret was hardcoded into the
configuration file itself.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

# Conservative heuristic: long, high-looking-entropy alphanumeric tokens.
# False positives are possible (e.g. long hashes); this is informational,
# not an automatic critical finding.
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-/+=]{24,}$")


_SENSITIVE_SECRET_KEY_EXACT = {
    "auth", "authorization", "key", "secret", "token", "password", "passwd",
    "credential", "credentials", "cookie", "setcookie", "clientsecret",
    "apikey", "accesskey", "accesskeyid", "privatekey", "secretaccesskey",
}
_SENSITIVE_SECRET_KEY_SUFFIXES = (
    "authorization", "accesstoken", "refreshtoken", "idtoken", "token",
    "clientsecret", "secret", "password", "passwd", "credentials",
    "credential", "apikey", "accesskeyid", "accesskey", "privatekey",
    "secretaccesskey", "cookie",
)


def _is_sensitive_secret_key(key: str) -> bool:
    """Check the field name rather than flagging arbitrary short values."""
    lowered = key.strip().lower()
    normalized = re.sub(r"[^a-z0-9]", "", lowered)
    if normalized in _SENSITIVE_SECRET_KEY_EXACT:
        return True
    if normalized.endswith(_SENSITIVE_SECRET_KEY_SUFFIXES):
        return True
    # Generic KEY is sensitive only when it is a standalone name or a
    # separator-delimited suffix; this avoids false positives like "monkey".
    return bool(re.search(r"(?:^|[_-])key$", lowered))


def _is_placeholder_or_reference(value: str) -> bool:
    """Whether a value is clearly a placeholder or runtime reference."""
    candidate = unquote(value).strip().strip("\\\"'").strip().lower()
    if not candidate or candidate.startswith("$") or "${" in candidate:
        return True
    if candidate in {
        "changeme", "example", "placeholder", "todo", "none", "null",
        "undefined", "redacted", "your-token", "your_api_key",
        "your-api-key", "replace_me", "replace-with-token",
    }:
        return True
    return candidate.startswith(("your_", "your-", "replace_", "replace-"))


def find_hardcoded_secret_like_values(values: Dict) -> List[Tuple[str, str]]:
    """Return key/value pairs whose string value resembles a hardcoded secret.

    Sensitive field names lower the detection threshold because even short
    values can be valid credentials. Runtime references and obvious placeholders
    are excluded before either the key-name or token-shape heuristic runs.
    """
    findings: List[Tuple[str, str]] = []
    if not isinstance(values, dict):
        return findings
    for key, value in values.items():
        if not isinstance(value, str) or not value.strip():
            continue
        if _is_placeholder_or_reference(value):
            continue

        candidate = value.strip()
        # Remote MCP configs often place a token in "Authorization: Bearer ...".
        # Inspect the token portion but keep the original value for redaction length.
        parts = candidate.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic"):
            candidate = parts[1].strip()
        if not candidate or _is_placeholder_or_reference(candidate):
            continue

        if _TOKEN_PATTERN.fullmatch(candidate) or _is_sensitive_secret_key(str(key)):
            findings.append((str(key), value))
    return findings


_SENSITIVE_URL_KEY_MARKERS = (
    "accesstoken", "refreshtoken", "token", "clientsecret", "secret",
    "password", "passwd", "apikey", "credential", "authorization",
    "signature", "privatekey", "accesskey",
)


def _is_sensitive_url_key(key: str) -> bool:
    """Match credential-bearing parameter names without substring false positives."""
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())

    # Exact names cover generic fields; suffixes cover common namespaced forms
    # such as github_token, client_secret, and X-Amz-Signature.
    exact_names = {
        "auth", "authkey", "key", "sig", "secret", "token", "password",
        "passwd", "credential", "credentials", "authorization", "signature",
    }
    if normalized in exact_names:
        return True

    sensitive_suffixes = (
        "accesstoken", "refreshtoken", "idtoken", "token",
        "clientsecret", "secret", "password", "passwd",
        "apikey", "credential", "authorization", "signature",
        "privatekey", "accesskey",
    )
    if normalized.endswith(sensitive_suffixes):
        return True

    # Preserve separator-based key forms (api_key, subscription-key) without
    # treating unrelated words ending in "key" (for example, "monkey") as secrets.
    return bool(re.search(r"(?i)(?:^|[_-])key(?:$|[_-])", key))


def find_hardcoded_url_credentials(url: str) -> List[Tuple[str, str]]:
    """Find literal credentials embedded in URL userinfo, query, or fragment.

    Returned values are internal-only, for reporting redacted lengths. Never
    interpolate a returned value into an output message.
    """
    findings: List[Tuple[str, str]] = []
    if not isinstance(url, str) or not url.strip():
        return findings
    try:
        parts = urlsplit(url.strip())
        if parts.password:
            password = unquote(parts.password)
            if not _is_placeholder_or_reference(password):
                findings.append(("url.userinfo.password", password))
        elif parts.username:
            # A username is not automatically a secret; flag it only if it
            # looks like a token rather than a normal account name.
            username = unquote(parts.username)
            if not _is_placeholder_or_reference(username) and _TOKEN_PATTERN.fullmatch(username):
                findings.append(("url.userinfo.username", username))

        for location, encoded_fields in (("query", parts.query), ("fragment", parts.fragment)):
            for key, value in parse_qsl(encoded_fields, keep_blank_values=True):
                if not _is_sensitive_url_key(key) or not value:
                    continue
                if _is_placeholder_or_reference(value):
                    continue
                safe_key = re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:64] or "credential"
                findings.append((f"url.{location}.{safe_key}", unquote(value)))
    except (ValueError, UnicodeError):
        # Malformed URLs should not crash the audit; parser/schema validation
        # handles their validity separately.
        return findings
    return findings
