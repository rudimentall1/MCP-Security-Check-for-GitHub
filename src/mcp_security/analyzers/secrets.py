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
        if value.startswith("${") or value.startswith("$"):
            continue  # references an external variable, not a literal
        if value.lower() in ("changeme", "example", "placeholder", "todo"):
            continue
        if _TOKEN_PATTERN.match(value):
            findings.append((str(key), value))
    return findings
