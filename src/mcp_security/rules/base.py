"""Rule engine base abstractions.

A Rule inspects a single :class:`Component` (with capabilities already
extracted) and yields zero or more :class:`Finding` objects. Rules must be
side-effect free and must never execute anything from the scanned content.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, List

from mcp_security.model.component import Component
from mcp_security.model.finding import Finding


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
