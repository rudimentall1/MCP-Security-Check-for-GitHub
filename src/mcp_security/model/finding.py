"""Finding model.

A Finding is the atomic unit of output produced by rules and analyzers.
Every finding must be self-explanatory: it should state *why* something is
risky, not just flag an occurrence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for sorting and score weighting."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


@dataclass
class Finding:
    """A single security finding.

    Attributes:
        rule_id: Stable identifier, e.g. "MSC001".
        title: Short human-readable title.
        severity: One of :class:`Severity`.
        description: Explanation of *why* this is risky (impact, not just
            the observation).
        evidence: The concrete data that triggered the finding (e.g. the
            capability id, config snippet key, or capability chain).
        file: Path of the file the finding relates to.
        line: Optional line number, if known.
        capability: Optional capability id most directly associated.
        remediation: Suggested fix or mitigation.
        component: Optional component name the finding relates to.
        confidence: Optional confidence level ("high", "medium", "low").
            Kept separate from severity: unknown/ambiguous data should
            reduce confidence, not automatically increase severity.
        metadata: Free-form extra data (e.g. attack path chain).
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: str
    file: str
    remediation: str
    line: Optional[int] = None
    capability: Optional[str] = None
    component: Optional[str] = None
    confidence: str = "high"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "file": self.file,
            "line": self.line,
            "capability": self.capability,
            "component": self.component,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }
