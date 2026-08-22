"""Capability risk tiering.

Provides a single, shared mapping from capability id to an intrinsic risk
tier. Used by the rule engine (for single-capability findings), the diff
engine (to flag newly introduced *high-risk* capabilities specifically),
and scoring.

This mapping is intentionally conservative and documented so severity is
not arbitrary -- see README "Risk scoring" section for rationale.
"""

from __future__ import annotations

from mcp_security.model.finding import Severity

# Capability id -> intrinsic severity if this capability appears at all,
# independent of combinations. Capabilities not listed here are treated as
# informational (no automatic finding) -- unknown/uncommon capabilities are
# not assumed dangerous.
CAPABILITY_BASE_SEVERITY = {
    "shell.execute": Severity.HIGH,
    "code.execute": Severity.HIGH,
    "filesystem.write": Severity.HIGH,
    "filesystem.delete": Severity.HIGH,
    "network.unrestricted": Severity.HIGH,
    "network.external": Severity.MEDIUM,
    "secrets.read": Severity.MEDIUM,
    "credentials.read": Severity.MEDIUM,
    "environment.read": Severity.LOW,
    "github.admin": Severity.HIGH,
    "github.write": Severity.MEDIUM,
    "package.install": Severity.MEDIUM,
    "package.execute": Severity.MEDIUM,
    "browser.execute": Severity.MEDIUM,
    "browser.download": Severity.LOW,
    "filesystem.read": Severity.INFO,
    "network.local": Severity.INFO,
    "github.read": Severity.INFO,
    "browser.navigate": Severity.INFO,
}

# Capabilities considered "high-risk" for the purposes of capability-diff
# escalation reporting (MSC015 - New High-Risk Capability), regardless of
# their exact base severity above.
HIGH_RISK_CAPABILITIES = {
    cap_id
    for cap_id, severity in CAPABILITY_BASE_SEVERITY.items()
    if severity in (Severity.CRITICAL, Severity.HIGH)
}


def base_severity_for(capability_id: str) -> Severity:
    return CAPABILITY_BASE_SEVERITY.get(capability_id, Severity.INFO)


def is_high_risk(capability_id: str) -> bool:
    return capability_id in HIGH_RISK_CAPABILITIES
