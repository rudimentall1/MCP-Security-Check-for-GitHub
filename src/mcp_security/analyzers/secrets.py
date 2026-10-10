"""Heuristics for hardcoded secret-like literal values in configuration.

This is separate from capability-based secret *access* detection (which
looks at env var names, see analyzers.capabilities). This module instead
flags values that look like an actual secret was hardcoded into the
configuration file itself.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Conservative heuristic: long, high-looking-entropy alphanumeric tokens.
# False positives are possible (e.g. long hashes); this is informational,
# not an automatic critical finding.
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-/+=]{24,}$")


def find_hardcoded_secret_like_values(env: Dict) -> List[Tuple[str, str]]:
    """Return (key, value) pairs whose *value* looks like a hardcoded secret.

    Only flags values, never keys -- a key named TOKEN with an empty or
    placeholder value (e.g. "${TOKEN}", "changeme") is not flagged.
    """
    findings: List[Tuple[str, str]] = []
    if not isinstance(env, dict):
        return findings
    for key, value in env.items():
        if not isinstance(value, str):
            continue
        # Configs commonly use ${input:...}, ${env:...}, or ${TOKEN} as
        # runtime references. Do not flag those as committed credentials,
        # including when a value has an HTTP auth scheme prefix.
        if value.startswith("$") or "${" in value:
            continue
        if value.lower() in ("changeme", "example", "placeholder", "todo"):
            continue

        candidate = value.strip()
        # Remote MCP configs often place a token in "Authorization: Bearer ...".
        # Inspect the token portion but keep the original value for redaction length.
        parts = candidate.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic"):
            candidate = parts[1].strip()
        if candidate.lower() in ("changeme", "example", "placeholder", "todo"):
            continue
        if _TOKEN_PATTERN.fullmatch(candidate):
            findings.append((str(key), value))
    return findings
