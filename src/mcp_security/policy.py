"""Policy loading and decision engine.

Policy controls:
- which severities cause BLOCK vs WARN vs ALLOW ("block_on" / "warn_on")
- per-rule action overrides (block/warn/allow/ignore a specific rule_id)
- allowed capability/endpoint lists (findings about an allowed item are
  suppressed)

Policy is intentionally simple (a small YAML file), not a general-purpose
policy-as-code system -- that is explicitly deferred to the v0.3 roadmap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import AttackPath, Decision

DEFAULT_BLOCK_ON = {Severity.CRITICAL}
DEFAULT_WARN_ON = {Severity.HIGH, Severity.MEDIUM}


@dataclass
class Policy:
    block_on: List[str] = field(default_factory=lambda: ["critical"])
    warn_on: List[str] = field(default_factory=lambda: ["high", "medium"])
    rule_overrides: Dict[str, str] = field(default_factory=dict)
    """rule_id -> one of "block" | "warn" | "allow" | "ignore" """
    allowed_capabilities: List[str] = field(default_factory=list)
    allowed_endpoints: List[str] = field(default_factory=list)
    block_on_critical_attack_path: bool = True

    @classmethod
    def load(cls, path: Optional[str]) -> "Policy":
        if not path:
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except FileNotFoundError:
            return cls()

        policy_data = data.get("policy", data) if isinstance(data, dict) else {}
        block_on = policy_data.get("block_on", ["critical"])
        warn_on = policy_data.get("warn_on", ["high", "medium"])

        rule_overrides: Dict[str, str] = {}
        rules_section = policy_data.get("rules", {}) or {}
        if isinstance(rules_section, dict):
            for rule_id, rule_cfg in rules_section.items():
                if isinstance(rule_cfg, dict) and "action" in rule_cfg:
                    rule_overrides[rule_id] = str(rule_cfg["action"]).lower()
                elif isinstance(rule_cfg, str):
                    rule_overrides[rule_id] = rule_cfg.lower()

        return cls(
            block_on=list(block_on),
            warn_on=list(warn_on),
            rule_overrides=rule_overrides,
            allowed_capabilities=list(policy_data.get("allowed_capabilities", []) or []),
            allowed_endpoints=list(policy_data.get("allowed_endpoints", []) or []),
            block_on_critical_attack_path=bool(policy_data.get("block_on_critical_attack_path", True)),
        )

    def apply_allowlist(self, findings: List[Finding]) -> List[Finding]:
        """Drop findings whose capability/evidence matches an allowlisted entry."""
        if not self.allowed_capabilities and not self.allowed_endpoints:
            return findings
        result = []
        for f in findings:
            if f.capability and f.capability in self.allowed_capabilities:
                continue
            if self.allowed_endpoints and any(ep in f.evidence for ep in self.allowed_endpoints):
                continue
            result.append(f)
        return result

    def apply_rule_overrides(self, findings: List[Finding]) -> List[Finding]:
        """Apply per-rule action overrides: ignore drops, block/warn adjust severity."""
        result: List[Finding] = []
        for f in findings:
            action = self.rule_overrides.get(f.rule_id)
            if action == "ignore":
                continue
            if action == "allow":
                f.severity = Severity.INFO
            elif action == "warn" and f.severity == Severity.CRITICAL:
                f.severity = Severity.HIGH
            elif action == "block":
                f.severity = Severity.CRITICAL
            result.append(f)
        return result


def decide(
    findings: List[Finding],
    attack_paths: List[AttackPath],
    policy: Policy,
) -> Decision:
    """Apply the decision engine.

    Default behavior: critical -> BLOCK, high/medium -> WARN, low/info ->
    ALLOW (contributes nothing). A critical attack path always forces
    BLOCK regardless of the block_on list, unless
    ``block_on_critical_attack_path`` is disabled in policy.
    """
    block_severities = {Severity(s) for s in policy.block_on}
    warn_severities = {Severity(s) for s in policy.warn_on}

    if policy.block_on_critical_attack_path:
        if any(p.severity == Severity.CRITICAL for p in attack_paths):
            return Decision.BLOCK

    if any(f.severity in block_severities for f in findings):
        return Decision.BLOCK

    if any(f.severity in warn_severities for f in findings):
        return Decision.WARN

    if attack_paths:
        # Any remaining (non-critical) attack path still deserves attention.
        return Decision.WARN

    return Decision.ALLOW
