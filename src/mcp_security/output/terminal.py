"""Human-readable terminal output."""

from __future__ import annotations

from mcp_security.model.report import Report

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def render_terminal(report: Report) -> str:
    lines = []
    lines.append("MCP SECURITY CHECK")
    lines.append("")
    lines.append(f"Decision: {report.decision.value}")
    lines.append(f"Risk Score: {report.risk_score}/100")
    lines.append("")

    summary = report.summary()
    for sev in _SEVERITY_ORDER:
        lines.append(f"{sev.capitalize()}: {summary.get(sev, 0)}")
    lines.append("")

    if report.capability_diff:
        diff = report.capability_diff
        if diff.added or diff.removed or diff.changed:
            lines.append("Permission Changes:")
            lines.append("")
            for cap in diff.added:
                lines.append(f"+ {cap}")
            for cap in diff.removed:
                lines.append(f"- {cap}")
            for change in diff.changed:
                lines.append(f"~ {change['capability']} ({change['before_target']} -> {change['after_target']})")
            lines.append("")

    if report.attack_paths:
        lines.append("Attack Paths:")
        lines.append("")
        for path in report.attack_paths:
            lines.append(f"[{path.severity.value.upper()}] {path.chain_str()}")
            lines.append(f"  {path.description}")
        lines.append("")

    if report.findings:
        lines.append("Findings:")
        lines.append("")
        for finding in report.findings:
            location = finding.file or "(diff)"
            lines.append(f"{finding.rule_id} [{finding.severity.value.upper()}] {finding.title} ({location})")
    else:
        lines.append("Findings: none")

    if report.errors:
        lines.append("")
        lines.append("Warnings during scan:")
        for err in report.errors:
            lines.append(f"  - {err}")

    return "\n".join(lines) + "\n"
