"""GitHub Actions workflow command annotations.

Emits ``::error``/``::warning``/``::notice`` workflow commands so findings
show up as inline annotations on the PR "Files changed" view, in addition
to the Markdown summary/comment and SARIF upload.

See: https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
"""

from __future__ import annotations

from typing import List

from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import Report

_SEVERITY_TO_COMMAND = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_annotations(report: Report) -> List[str]:
    lines: List[str] = []
    for finding in report.findings:
        command = _SEVERITY_TO_COMMAND[finding.severity]
        params = []
        if finding.file:
            params.append(f"file={finding.file}")
        if finding.line:
            params.append(f"line={finding.line}")
        param_str = f" {','.join(params)}" if params else ""
        message = _escape(f"[{finding.rule_id}] {finding.title}: {finding.description}")
        lines.append(f"::{command}{param_str}::{message}")
    return lines
