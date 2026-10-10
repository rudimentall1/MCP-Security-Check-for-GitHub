"""Top-level report model.

The Report is the final aggregate produced by the engine: decision, risk
score, findings, attack paths and (optionally) a capability diff summary.
All output formats (JSON/Markdown/SARIF/terminal) are rendered from this
single object so they stay consistent with one another.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from mcp_security.model.finding import Finding, Severity
from mcp_security.redaction import redact_sensitive_text, redact_sensitive_value


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

    @property
    def exit_code(self) -> int:
        return {Decision.ALLOW: 0, Decision.WARN: 1, Decision.BLOCK: 2}[self]


@dataclass
class AttackPath:
    """A detected chain of capabilities that together form an attack path."""

    path_id: str
    severity: Severity
    chain: List[str]
    description: str
    remediation: str = ""

    def chain_str(self) -> str:
        return " → ".join(self.chain)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "severity": self.severity.value,
            "chain": self.chain,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class CapabilityDiffSummary:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)
    changed: List[Dict[str, Any]] = field(default_factory=list)
    """List of {"capability": id, "before_target": ..., "after_target": ...}"""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added": self.added,
            "removed": self.removed,
            "unchanged": self.unchanged,
            "changed": self.changed,
        }


@dataclass
class Report:
    decision: Decision
    risk_score: int
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    capability_diff: Optional[CapabilityDiffSummary] = None
    scanned_files: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    """Names of components discovered/analyzed, for informational purposes."""
    errors: List[str] = field(default_factory=list)
    """Read/parse errors. Any such error makes the overall scan fail closed."""

    def __post_init__(self) -> None:
        # All report formats consume this shared object. Sanitize every
        # user-controlled string here so individual renderers cannot diverge.
        self.scanned_files = [redact_sensitive_text(value) or "" for value in self.scanned_files]
        self.components = [redact_sensitive_text(value) or "" for value in self.components]
        self.errors = [redact_sensitive_text(value) or "" for value in self.errors]

        for path in self.attack_paths:
            path.chain = [redact_sensitive_text(value) or "" for value in path.chain]
            path.description = redact_sensitive_text(path.description) or ""
            path.remediation = redact_sensitive_text(path.remediation) or ""

        if self.capability_diff is not None:
            diff = self.capability_diff
            diff.added = [redact_sensitive_text(value) or "" for value in diff.added]
            diff.removed = [redact_sensitive_text(value) or "" for value in diff.removed]
            diff.unchanged = [redact_sensitive_text(value) or "" for value in diff.unchanged]
            diff.changed = redact_sensitive_value(diff.changed)

    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "summary": self.summary(),
            "capability_diff": self.capability_diff.to_dict() if self.capability_diff else None,
            "capabilities_added": self.capability_diff.added if self.capability_diff else [],
            "findings": [f.to_dict() for f in self.findings],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "scanned_files": self.scanned_files,
            "components": self.components,
            "errors": self.errors,
        }
