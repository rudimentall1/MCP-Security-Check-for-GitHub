"""Capability diff engine.

Compares two sets of components (BASE vs HEAD) and computes added/removed/
unchanged/changed capabilities, plus diff-specific findings:

- MSC015 New High-Risk Capability: a high-risk capability appears in HEAD
  that was not present in BASE.
- MSC018 New External Endpoint: a new ``network.external`` capability
  with a target (endpoint) not seen in BASE.
- MSC020 Configuration Drift: a capability's target changed between BASE
  and HEAD without the capability itself being added/removed (e.g. a
  filesystem write scope widened).

This module is independent of GitHub -- it operates purely on capability
sets, so the CLI's ``diff`` subcommand can use it directly.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from mcp_security.analyzers.permissions import is_high_risk
from mcp_security.model.capability import Capability
from mcp_security.model.component import Component
from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import CapabilityDiffSummary
from mcp_security.redaction import redact_sensitive_text

MSC015 = "MSC015"
MSC018 = "MSC018"
MSC020 = "MSC020"


def _capability_map(components: Iterable[Component]) -> Dict[str, Capability]:
    """Flatten all components' capabilities into (component_name, id) -> Capability.

    Component identity is preserved so that the same capability id declared
    by different components does not collide. Target changes are detected
    per-component rather than being lost when multiple components share
    a capability id.
    """
    result: Dict[str, Capability] = {}
    for component in components:
        for cap in component.capabilities:
            key = f"{component.name}::{cap.id}"
            result[key] = cap
    return result


def diff_components(
    base_components: Iterable[Component],
    head_components: Iterable[Component],
) -> Tuple[CapabilityDiffSummary, List[Finding]]:
    base_caps = _capability_map(base_components)
    head_caps = _capability_map(head_components)

    base_ids = set(base_caps.keys())
    head_ids = set(head_caps.keys())

    # Extract pure capability ids for the summary (preserving existing API)
    added = sorted({head_caps[k].id for k in head_ids - base_ids})
    removed = sorted({base_caps[k].id for k in base_ids - head_ids})
    unchanged_ids = sorted(base_ids & head_ids)

    unchanged: List[str] = []
    changed: List[Dict] = []
    for cap_key in unchanged_ids:
        before = base_caps[cap_key]
        after = head_caps[cap_key]
        cap_id = before.id
        if before.target != after.target:
            changed.append(
                {
                    "capability": cap_id,
                    "before_target": redact_sensitive_text(before.target),
                    "after_target": redact_sensitive_text(after.target),
                }
            )
        else:
            unchanged.append(cap_id)

    summary = CapabilityDiffSummary(added=added, removed=removed, unchanged=unchanged, changed=changed)
    findings = _diff_findings(added, changed, head_caps)
    return summary, findings


def _diff_findings(added: List[str], changed: List[Dict], head_caps: Dict[str, Capability]) -> List[Finding]:
    findings: List[Finding] = []

    for cap_id in added:
        # Find the capability by id in head_caps
        cap = None
        for key, candidate in head_caps.items():
            if candidate.id == cap_id:
                cap = candidate
                break
        if cap is None:
            continue
        if is_high_risk(cap_id):
            findings.append(
                Finding(
                    rule_id=MSC015,
                    title="New High-Risk Capability",
                    severity=Severity.HIGH,
                    description=f"The pull request introduces a new high-risk capability: {cap_id}. This was not present in the base branch.",
                    evidence=f"added_capability={cap_id}",
                    file=cap.metadata.get("file", "") if cap.metadata else "",
                    capability=cap_id,
                    remediation="Review why this new capability is required before merging.",
                )
            )
        if cap_id == "network.external":
            endpoint = redact_sensitive_text(cap.target) or "unknown endpoint"
            findings.append(
                Finding(
                    rule_id=MSC018,
                    title="New External Endpoint",
                    severity=Severity.MEDIUM,
                    description=f"The pull request introduces a new external network endpoint: {endpoint}.",
                    evidence=f"endpoint={endpoint}",
                    file="",
                    capability=cap_id,
                    remediation="Confirm this endpoint is expected and add it to the allowlist policy if legitimate.",
                )
            )

    for change in changed:
        findings.append(
            Finding(
                rule_id=MSC020,
                title="Configuration Drift",
                severity=Severity.LOW,
                description=(
                    f"The scope/target of capability '{change['capability']}' changed "
                    f"from '{change['before_target']}' to '{change['after_target']}' "
                    "between base and head."
                ),
                evidence=f"{change['before_target']} -> {change['after_target']}",
                file="",
                capability=change["capability"],
                confidence="medium",
                remediation="Confirm the widened/changed scope is intentional and necessary.",
            )
        )

    return findings
