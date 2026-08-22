"""SARIF (Static Analysis Results Interchange Format) output.

Produces SARIF 2.1.0 suitable for GitHub code scanning. Structure is
validated by tests (tests/test_outputs.py) against the required top-level
shape rather than a full external schema (no network access needed to
validate).
"""

from __future__ import annotations

from typing import Any, Dict

from mcp_security.model.finding import Severity
from mcp_security.model.report import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(report: Report, *, tool_version: str = "0.1.0") -> Dict[str, Any]:
    rules_index: Dict[str, int] = {}
    rule_defs = []

    for finding in report.findings:
        if finding.rule_id not in rules_index:
            rules_index[finding.rule_id] = len(rule_defs)
            rule_defs.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.remediation},
                    "defaultConfiguration": {"level": _SEVERITY_TO_SARIF_LEVEL[finding.severity]},
                }
            )

    results = []
    for finding in report.findings:
        artifact_path = finding.file or "capability-diff"
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rules_index[finding.rule_id],
                "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_path},
                            "region": {"startLine": finding.line or 1},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-security-check",
                        "informationUri": "https://github.com/rudimentall1/MCP-Security-Check-for-GitHub",
                        "version": tool_version,
                        "rules": rule_defs,
                    }
                },
                "results": results,
            }
        ],
    }
