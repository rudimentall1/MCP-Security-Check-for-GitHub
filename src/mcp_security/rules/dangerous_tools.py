from __future__ import annotations

import base64
import re
from typing import List

from mcp_security.analyzers.provenance import evaluate_provenance
from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.rules.base import Rule

# "curl ... | sh"-style patterns: fetch a script and pipe straight into an
# interpreter. This is a much stronger signal than shell.execute alone.
_REMOTE_PIPE_PATTERN = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash|zsh|python3?|node)\b", re.IGNORECASE)

_DANGEROUS_TOOL_NAME_PATTERN = re.compile(
    r"(?i)(run[_-]?shell|exec[_-]?command|eval|raw[_-]?exec|shell[_-]?raw)"
)

_INSTRUCTION_FETCH_PATTERN = re.compile(r"(?i)(fetch|load|download).{0,40}(instructions?|prompt)")

_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


class RemoteScriptExecutionRule(Rule):
    """MSC008 - Remote Script Execution.

    Fires when the launch command matches a "download and pipe to an
    interpreter" pattern (e.g. ``curl https://... | sh``). This is a
    well-known, high-confidence indicator of remote code execution risk.
    """

    rule_id = "MSC008"
    title = "Remote Script Execution"

    def evaluate(self, component: Component) -> List[Finding]:
        raw = component.raw or {}
        tokens = [str(raw.get("command") or "")] + [str(a) for a in (raw.get("args") or [])]
        joined = " ".join(tokens)
        if _REMOTE_PIPE_PATTERN.search(joined):
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    description=(
                        "The launch command downloads a remote script and pipes it "
                        "directly into an interpreter. This executes unreviewed remote "
                        "code with no integrity check."
                    ),
                    evidence=joined.strip(),
                    file=component.file,
                    component=component.name,
                    remediation="Never pipe a downloaded script directly into a shell/interpreter; pin and verify (checksum/signature) any downloaded artifact before executing it.",
                )
            ]
        return []


class DynamicCodeExecutionRule(Rule):
    """MSC011 - Dynamic Code Execution."""

    rule_id = "MSC011"
    title = "Dynamic Code Execution"

    def evaluate(self, component: Component) -> List[Finding]:
        findings: List[Finding] = []
        for cap in component.capabilities:
            if cap.id == "code.execute":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description="This component launches a general-purpose language runtime (e.g. python/node) that can execute arbitrary code.",
                        evidence=f"capability={cap}",
                        file=component.file,
                        capability=cap.id,
                        component=component.name,
                        remediation="Verify the launched script is pinned/reviewed; avoid launching interpreters with dynamically-supplied code paths.",
                    )
                )
        return findings


class DangerousMcpToolRule(Rule):
    """MSC012 - Dangerous MCP Tool.

    Fires when a declared tool name itself signals a raw execution
    primitive (e.g. "run_shell", "eval"), independent of whether we could
    infer a capability from it.
    """

    rule_id = "MSC012"
    title = "Dangerous MCP Tool"

    def evaluate(self, component: Component) -> List[Finding]:
        raw = component.raw or {}
        tools = raw.get("tools") or []
        findings: List[Finding] = []
        for tool in tools:
            name = tool if isinstance(tool, str) else (tool.get("name") if isinstance(tool, dict) else None)
            if name and _DANGEROUS_TOOL_NAME_PATTERN.search(str(name)):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        description=f"The declared tool name '{name}' suggests a raw/unrestricted execution primitive.",
                        evidence=f"tool={name}",
                        file=component.file,
                        component=component.name,
                        remediation="Review this tool's implementation; prefer narrow, purpose-specific tools over generic execution primitives.",
                    )
                )
        return findings


class ExternalInstructionFetchRule(Rule):
    """MSC013 - External Instruction Fetch.

    Fires when tool/description metadata suggests the component fetches
    its own instructions/prompt content from an external source at
    runtime -- a known prompt-injection / instruction-tampering vector.
    """

    rule_id = "MSC013"
    title = "External Instruction Fetch"

    def evaluate(self, component: Component) -> List[Finding]:
        description = str((component.metadata or {}).get("description") or "")
        findings: List[Finding] = []
        if _INSTRUCTION_FETCH_PATTERN.search(description):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description="The component's declared description suggests it fetches or loads instructions/prompt content from an external source at runtime, which can enable instruction tampering.",
                    evidence=description[:200],
                    file=component.file,
                    component=component.name,
                    confidence="low",
                    remediation="Prefer static, reviewed instructions bundled with the component instead of fetching them at runtime.",
                )
            )
        return findings


class ObfuscatedInstructionRule(Rule):
    """MSC014 - Obfuscated Instruction.

    Fires when a long base64-looking blob is found in component metadata
    (description/name). This is a heuristic hint, not proof of malicious
    intent -- legitimate binary data can also match this pattern, hence
    LOW confidence.
    """

    rule_id = "MSC014"
    title = "Obfuscated Instruction"

    def evaluate(self, component: Component) -> List[Finding]:
        description = str((component.metadata or {}).get("description") or "")
        match = _BASE64_BLOB_PATTERN.search(description)
        if not match:
            return []
        blob = match.group(0)
        decodes_cleanly = _looks_like_decodable_text(blob)
        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM if decodes_cleanly else Severity.LOW,
                description=(
                    "A long base64-like blob was found in component metadata. This may "
                    "hide instructions from casual review."
                ),
                evidence=f"blob_length={len(blob)}",
                file=component.file,
                component=component.name,
                confidence="low",
                remediation="Avoid embedding encoded/obfuscated content in configuration metadata; keep instructions in plain, reviewable text.",
            )
        ]


def _looks_like_decodable_text(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "===", validate=False)
        decoded.decode("utf-8")
        return True
    except Exception:
        return False


class UnpinnedDependencyRule(Rule):
    """MSC016 - Unpinned Dependency."""

    rule_id = "MSC016"
    title = "Unpinned Dependency"

    def evaluate(self, component: Component) -> List[Finding]:
        for signal in evaluate_provenance(component):
            if signal.name == "version_pinned" and not signal.present:
                return [
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        description="No pinned version was declared for this component (or it uses 'latest'), so its content can change without review.",
                        evidence=signal.note,
                        file=component.file,
                        component=component.name,
                        confidence="medium",
                        remediation="Pin an explicit version/commit for this component.",
                    )
                ]
        return []


class UnverifiedRemoteSourceRule(Rule):
    """MSC017 - Unverified Remote Source."""

    rule_id = "MSC017"
    title = "Unverified Remote Source"

    def evaluate(self, component: Component) -> List[Finding]:
        signals = {s.name: s for s in evaluate_provenance(component)}
        locality = signals.get("source_locality")
        publisher = signals.get("publisher_declared")
        if locality and not locality.present and publisher and not publisher.present:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description="This component is fetched from a remote source with no declared publisher metadata, so its provenance cannot be verified locally.",
                    evidence=f"{locality.note}; {publisher.note}",
                    file=component.file,
                    component=component.name,
                    confidence="medium",
                    remediation="Prefer components with verifiable publisher/source metadata, or vendor and pin the component locally.",
                )
            ]
        return []


class UnknownPublisherRule(Rule):
    """MSC019 - Unknown Publisher."""

    rule_id = "MSC019"
    title = "Unknown Publisher"

    def evaluate(self, component: Component) -> List[Finding]:
        for signal in evaluate_provenance(component):
            if signal.name == "publisher_declared" and not signal.present:
                return [
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.LOW,
                        description="No publisher metadata is declared for this component.",
                        evidence=signal.note,
                        file=component.file,
                        component=component.name,
                        confidence="low",
                        remediation="Declare publisher metadata where possible to aid provenance review.",
                    )
                ]
        return []
