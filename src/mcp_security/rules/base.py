"""Rule engine base abstractions.

A Rule inspects a single :class:`Component` (with capabilities already
extracted) and yields zero or more :class:`Finding` objects. Rules must be
side-effect free and must never execute anything from the scanned content.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List

from mcp_security.model.capability import Capability
from mcp_security.model.component import Component
from mcp_security.model.finding import Finding


def unique_capabilities_by_id(component: Component) -> List[Capability]:
    """Return at most one :class:`Capability` per distinct capability id.

    A component's capability *extraction* can legitimately produce more than
    one :class:`Capability` instance with the same id but a different
    ``target`` (e.g. ``shell.execute`` inferred both from the launch command
    and from a declared tool name). That distinction is meaningful for the
    capability diff (see diff/capability_diff.py, which reports every
    distinct target) and for evidence detail, but a single-capability rule
    (MSC001, MSC002, MSC006, MSC007, MSC009, MSC011, ...) should report the
    *capability* being dangerous, not one finding per surface that exposes
    it -- otherwise the same rule fires multiple times for one component,
    inflating both the finding count and the risk score without adding new
    information.

    The first Capability seen for a given id wins (deterministic: follows
    extraction order), and is used only as a representative for
    evidence/target purposes.
    """
    result: Dict[str, Capability] = {}
    for cap in component.capabilities:
        result.setdefault(cap.id, cap)
    return list(result.values())


class Rule(ABC):
    """Base class for all security rules."""

    rule_id: str
    title: str

    @abstractmethod
    def evaluate(self, component: Component) -> List[Finding]:
        """Return findings for this rule against ``component``. May be empty."""
        raise NotImplementedError


class RuleEngine:
    """Runs a set of rules against a set of components."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules: List[Rule] = list(rules)

    def run(self, components: Iterable[Component]) -> List[Finding]:
        findings: List[Finding] = []
        for component in components:
            for rule in self.rules:
                findings.extend(rule.evaluate(component))
        return findings
