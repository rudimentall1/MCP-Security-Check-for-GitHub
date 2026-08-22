"""Scan orchestration.

Ties together: Discovery -> Parser -> Normalized Model -> Capabilities ->
Rules -> Attack Path Analysis -> Risk Scoring -> Decision -> Report.

This is the single entry point used by both the CLI and the GitHub Action
wrapper, so both interfaces produce identical results for the same input.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from mcp_security.analyzers.attack_paths import detect_attack_paths
from mcp_security.analyzers.capabilities import extract_capabilities
from mcp_security.discovery.mcp import discover_mcp_files
from mcp_security.model.component import Component
from mcp_security.model.finding import Finding
from mcp_security.model.report import Decision, Report
from mcp_security.parsers.json_parser import parse_json_file
from mcp_security.parsers.yaml_parser import parse_yaml_file
from mcp_security.policy import Policy, decide
from mcp_security.rules import build_default_engine
from mcp_security.scoring.risk import compute_risk_score, has_new_high_risk_capability


@dataclass
class ScanResult:
    components: List[Component]
    errors: List[str]
    scanned_files: List[str]


def load_components(root: str, *, explicit_paths: Optional[List[str]] = None) -> ScanResult:
    """Discover, parse, and extract capabilities for all MCP config in ``root``."""
    discovered = discover_mcp_files(root, explicit_paths=explicit_paths)
    components: List[Component] = []
    errors: List[str] = []
    scanned_files: List[str] = []

    for file in discovered:
        scanned_files.append(file.relative_path)
        try:
            with open(file.path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            errors.append(f"{file.relative_path}: could not read file ({exc})")
            continue

        if file.relative_path.endswith((".yaml", ".yml")):
            parsed_components, parse_errors = parse_yaml_file(content, file.relative_path)
        else:
            parsed_components, parse_errors = parse_json_file(content, file.relative_path)

        errors.extend(parse_errors)
        for component in parsed_components:
            component.capabilities = extract_capabilities(component)
            components.append(component)

    return ScanResult(components=components, errors=errors, scanned_files=scanned_files)


def scan(root: str, *, config_path: Optional[str] = None, explicit_paths: Optional[List[str]] = None) -> Report:
    """Run a full single-tree scan and return a :class:`Report`."""
    result = load_components(root, explicit_paths=explicit_paths)
    policy = Policy.load(config_path)

    engine = build_default_engine()
    findings: List[Finding] = engine.run(result.components)

    all_capability_ids = set()
    for component in result.components:
        all_capability_ids.update(c.id for c in component.capabilities)
    attack_paths = detect_attack_paths(all_capability_ids)

    findings = policy.apply_rule_overrides(findings)
    findings = policy.apply_allowlist(findings)

    risk_score = compute_risk_score(findings, attack_paths, has_high_risk_escalation=False)
    decision = decide(findings, attack_paths, policy)

    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))

    return Report(
        decision=decision,
        risk_score=risk_score,
        findings=findings,
        attack_paths=attack_paths,
        capability_diff=None,
        scanned_files=result.scanned_files,
        components=[c.name for c in result.components],
        errors=result.errors,
    )


def scan_diff(
    base_root: str,
    head_root: str,
    *,
    config_path: Optional[str] = None,
) -> Report:
    """Run a BASE-vs-HEAD scan: parses both trees, computes the capability
    diff, runs rules against HEAD, and merges diff-specific findings
    (MSC015/MSC018/MSC020) into the report.
    """
    from mcp_security.diff.capability_diff import diff_components

    base_result = load_components(base_root)
    head_result = load_components(head_root)
    policy = Policy.load(config_path)

    engine = build_default_engine()
    head_findings: List[Finding] = engine.run(head_result.components)

    diff_summary, diff_findings = diff_components(base_result.components, head_result.components)

    all_findings = head_findings + diff_findings
    all_findings = policy.apply_rule_overrides(all_findings)
    all_findings = policy.apply_allowlist(all_findings)

    head_capability_ids = set()
    for component in head_result.components:
        head_capability_ids.update(c.id for c in component.capabilities)
    attack_paths = detect_attack_paths(head_capability_ids)

    escalation = has_new_high_risk_capability(all_findings)
    risk_score = compute_risk_score(all_findings, attack_paths, has_high_risk_escalation=escalation)
    decision = decide(all_findings, attack_paths, policy)

    all_findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))

    return Report(
        decision=decision,
        risk_score=risk_score,
        findings=all_findings,
        attack_paths=attack_paths,
        capability_diff=diff_summary,
        scanned_files=sorted(set(base_result.scanned_files) | set(head_result.scanned_files)),
        components=[c.name for c in head_result.components],
        errors=base_result.errors + head_result.errors,
    )
