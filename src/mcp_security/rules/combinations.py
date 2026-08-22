from __future__ import annotations

from typing import List

from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule


def _has(component: Component, capability_id: str) -> bool:
    return capability_id in {c.id for c in component.capabilities}


class _PairCombinationRule(Rule):
    """Shared implementation for "capability A + capability B" rules.

    These are intentionally simpler/coarser than the Attack Path Engine
    (analyzers/attack_paths.py): they report a *finding* for a risky pair
    on a single component, while the attack-path engine additionally
    reasons about ordered chains and multi-step (3+) combinations across
    the full chain description. Keeping both gives users both a flat
    finding list and a narrative chain view.
    """

    cap_a: str
    cap_b: str

    def evaluate(self, component: Component) -> List[Finding]:
        if _has(component, self.cap_a) and _has(component, self.cap_b):
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    description=self.description_text,
                    evidence=f"capabilities={self.cap_a}+{self.cap_b}",
                    file=component.file,
                    component=component.name,
                    remediation=self.remediation_text,
                )
            ]
        return []


class SecretAndExternalNetworkRule(_PairCombinationRule):
    """MSC003 - Secret + External Network."""

    rule_id = "MSC003"
    title = "Secret Access + External Network"
    cap_a = "secrets.read"
    cap_b = "network.external"
    description_text = (
        "This component can read secret material AND reach external networks in "
        "the same component. This combination enables credential/data exfiltration."
    )
    remediation_text = "Separate secret access and external network access into different components, or restrict network egress."


class FilesystemAndExternalNetworkRule(_PairCombinationRule):
    """MSC004 - Filesystem + External Network."""

    rule_id = "MSC004"
    title = "Filesystem Access + External Network"
    cap_a = "filesystem.read"
    cap_b = "network.external"
    description_text = (
        "This component can read local files AND reach external networks in the "
        "same component. This combination enables local data exfiltration."
    )
    remediation_text = "Restrict network egress to a strict allowlist, or scope filesystem access to non-sensitive directories."

    def evaluate(self, component: Component) -> List[Finding]:
        findings = super().evaluate(component)
        for f in findings:
            f.severity = Severity.HIGH  # filesystem.read is lower-risk than secrets/credentials
        return findings


class ShellAndExternalNetworkRule(_PairCombinationRule):
    """MSC005 - Shell + External Network."""

    rule_id = "MSC005"
    title = "Shell Execution + External Network"
    cap_a = "shell.execute"
    cap_b = "network.external"
    description_text = (
        "This component can execute shell commands AND reach external networks in "
        "the same component. This combination enables remote payload execution "
        "and/or exfiltration."
    )
    remediation_text = "Remove shell execution if not required, or restrict network egress to a strict allowlist."


class PackageInstallAndExecuteRule(_PairCombinationRule):
    """MSC010 - Package Install + Execute."""

    rule_id = "MSC010"
    title = "Package Install + Execute"
    cap_a = "package.install"
    cap_b = "package.execute"
    description_text = (
        "This component can both install and execute packages, enabling arbitrary "
        "third-party (supply-chain) code execution."
    )
    remediation_text = "Pin dependency versions and verify sources before allowing install+execute together."

    def evaluate(self, component: Component) -> List[Finding]:
        findings = super().evaluate(component)
        for f in findings:
            f.severity = Severity.HIGH
        return findings
