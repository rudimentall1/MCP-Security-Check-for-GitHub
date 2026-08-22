from __future__ import annotations

from typing import List

from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule


class ArbitraryShellExecutionRule(Rule):
    """MSC001 - Arbitrary Shell Execution.

    Fires when a component can execute arbitrary shell commands. Shell
    execution is a powerful primitive: combined with other capabilities it
    enables most attack paths in this engine (see rules/combinations.py and
    analyzers/attack_paths.py). On its own it is HIGH, not CRITICAL --
    many legitimate MCP servers run local build/test tooling via a shell.
    """

    rule_id = "MSC001"
    title = "Arbitrary Shell Execution"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in component.capabilities:
            if cap.id == "shell.execute":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description=(
                            "This component can execute arbitrary shell commands. "
                            "This is a dangerous capability, not proof of malware -- "
                            "review whether shell access is actually required."
                        ),
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        remediation=(
                            "Remove shell execution if not required, or restrict it to a "
                            "fixed, non-configurable command with no external input."
                        ),
                    )
                )
        return findings
