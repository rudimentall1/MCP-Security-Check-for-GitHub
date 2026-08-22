from __future__ import annotations

from typing import List

from mcp_security.analyzers.secrets import find_hardcoded_secret_like_values
from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule, unique_capabilities_by_id


class SecretAccessRule(Rule):
    """MSC002 - Secret Access.

    Fires when a component reads environment variables that look like
    secrets (based on variable naming, e.g. *_TOKEN, *_API_KEY). This is a
    capability-level finding; combined with network access it escalates
    via the attack-path engine (AP001/AP006).
    """

    rule_id = "MSC002"
    title = "Secret Access"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in unique_capabilities_by_id(component):
            if cap.id == "secrets.read":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        description=(
                            "This component reads an environment variable whose name "
                            "suggests it holds secret material (token/key/password/etc)."
                        ),
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        confidence="medium",
                        remediation="Confirm the referenced secret is actually required by this component and scoped to least privilege.",
                    )
                )
        return findings


class CredentialFileAccessRule(Rule):
    """MSC007 - Credential File Access.

    Fires when a component declares explicit credentials.read access
    (typically via a declared permissions block, as opposed to inferred
    env-var naming which is covered by MSC002).
    """

    rule_id = "MSC007"
    title = "Credential File Access"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in unique_capabilities_by_id(component):
            if cap.id == "credentials.read":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        description="This component declares access to credential material.",
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        remediation="Confirm credential access is required and scoped to the minimum needed.",
                    )
                )
        return findings


class HardcodedSecretRule(Rule):
    """Informational: hardcoded secret-like literal value found in config.

    Not part of the numbered MSC00x capability rules (this checks literal
    values, not capabilities), but reported the same way for visibility.
    Kept LOW/INFO-leaning because entropy-based detection has false
    positives; this is a hint for manual review, not a certainty.
    """

    rule_id = "MSC002-LITERAL"
    title = "Possible Hardcoded Secret"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        raw = component.raw or {}
        env = raw.get("env") or {}
        for key, value in find_hardcoded_secret_like_values(env):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The environment variable '{key}' has a literal value that looks "
                        "like a hardcoded secret rather than a reference to an external "
                        "variable. This may indicate a leaked credential committed to the repository."
                    ),
                    evidence=f"env.{key}=<redacted, {len(value)} chars>",
                    file=component.file,
                    component=component.name,
                    confidence="low",
                    remediation="Move the secret to a proper secret store / CI secret and reference it, do not hardcode it in configuration.",
                )
            )
        return findings
