from __future__ import annotations

from typing import List

from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule, unique_capabilities_by_id


class UnrestrictedFilesystemWriteRule(Rule):
    """MSC006 - Unrestricted Filesystem Write.

    Fires when a component can write to the filesystem. HIGH rather than
    CRITICAL on its own: write access scoped to a workspace is common and
    often legitimate (e.g. editors, formatters). Combined with network or
    shell capabilities, this escalates via attack-path detection instead.
    """

    rule_id = "MSC006"
    title = "Unrestricted Filesystem Write"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in unique_capabilities_by_id(component):
            if cap.id == "filesystem.write":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description=(
                            "This component can write files. If the write scope is not "
                            "restricted, this may allow overwriting arbitrary files, "
                            "configuration, or persistence mechanisms."
                        ),
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        remediation="Scope filesystem write access to a specific directory rather than the whole workspace/filesystem.",
                    )
                )
        return findings
