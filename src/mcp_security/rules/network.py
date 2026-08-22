from __future__ import annotations

from typing import List

from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule


class UnrestrictedNetworkRule(Rule):
    """MSC009 - Unrestricted Network.

    Fires when a component declares unrestricted network access (as
    opposed to a specific external endpoint). This is treated as more
    severe than a single known external endpoint because the blast radius
    of "any network destination" is much larger.
    """

    rule_id = "MSC009"
    title = "Unrestricted Network Access"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in component.capabilities:
            if cap.id == "network.unrestricted":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description=(
                            "This component declares unrestricted network access, i.e. it "
                            "is not limited to a specific endpoint. This significantly "
                            "increases exfiltration and command-and-control risk."
                        ),
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        remediation="Restrict network access to an explicit allowlist of required endpoints.",
                    )
                )
        return findings
