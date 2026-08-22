"""Transparent, reproducible risk scoring.

The score is NOT an opaque AI/ML output. It is a documented weighted sum,
capped at 100, so the same findings always produce the same score and the
formula can be audited.

Formula:

    score = sum(weight[severity] for each finding)
          + attack_path_bonus
          + escalation_bonus
    score = min(score, 100)

Where:
    weight = {critical: 40, high: 20, medium: 10, low: 3, info: 0}

    attack_path_bonus:
        +25 per CRITICAL attack path
        +12 per HIGH attack path
        (other severities contribute 0 extra beyond their own finding, if any)

    escalation_bonus:
        +15 if any newly-added capability is high-risk (MSC015 present)

These weights intentionally make a single CRITICAL finding (40) plus one
CRITICAL attack path (25) already exceed common BLOCK thresholds, while a
handful of LOW/INFO findings alone cannot reach WARN/BLOCK territory.
"""

from __future__ import annotations

from typing import Iterable, List

from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import AttackPath

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

ATTACK_PATH_BONUS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 0,
    Severity.INFO: 0,
}

ESCALATION_BONUS = 15
MAX_SCORE = 100


def compute_risk_score(
    findings: Iterable[Finding],
    attack_paths: Iterable[AttackPath],
    *,
    has_high_risk_escalation: bool = False,
) -> int:
    findings = list(findings)
    attack_paths = list(attack_paths)

    score = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    score += sum(ATTACK_PATH_BONUS[p.severity] for p in attack_paths)
    if has_high_risk_escalation:
        score += ESCALATION_BONUS

    return min(score, MAX_SCORE)


def has_new_high_risk_capability(findings: Iterable[Finding]) -> bool:
    return any(f.rule_id == "MSC015" for f in findings)
