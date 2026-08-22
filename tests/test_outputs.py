import json

from mcp_security.model.finding import Finding, Severity
from mcp_security.model.report import AttackPath, CapabilityDiffSummary, Decision, Report
from mcp_security.output.markdown import render_markdown
from mcp_security.output.sarif import render_sarif
from mcp_security.output.terminal import render_terminal


def make_report():
    finding = Finding(
        rule_id="MSC001",
        title="Arbitrary Shell Execution",
        severity=Severity.CRITICAL,
        description="desc",
        evidence="ev",
        file="mcp.json",
        remediation="fix it",
        line=3,
    )
    attack_path = AttackPath(
        path_id="AP004",
        severity=Severity.CRITICAL,
        chain=["shell.execute", "network.external"],
        description="chain desc",
    )
    diff = CapabilityDiffSummary(added=["shell.execute"], removed=[], unchanged=[], changed=[])
    return Report(
        decision=Decision.BLOCK,
        risk_score=87,
        findings=[finding],
        attack_paths=[attack_path],
        capability_diff=diff,
        scanned_files=["mcp.json"],
        components=["srv"],
    )


def test_report_to_dict_has_expected_keys():
    report = make_report()
    d = report.to_dict()
    for key in ("decision", "risk_score", "summary", "capabilities_added", "findings", "attack_paths"):
        assert key in d
    assert d["decision"] == "BLOCK"
    assert d["risk_score"] == 87


def test_report_json_is_serializable():
    report = make_report()
    text = json.dumps(report.to_dict())
    reloaded = json.loads(text)
    assert reloaded["decision"] == "BLOCK"


def test_terminal_output_contains_decision_and_score():
    text = render_terminal(make_report())
    assert "Decision: BLOCK" in text
    assert "Risk Score: 87/100" in text
    assert "MSC001" in text


def test_markdown_output_contains_table_and_findings():
    text = render_markdown(make_report())
    assert "## 🛡️ MCP Security Check" in text
    assert "MSC001" in text
    assert "| Capability | Change | Risk |" in text
    assert "shell.execute" in text


def test_sarif_output_has_required_top_level_shape():
    sarif = render_sarif(make_report())
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-security-check"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "MSC001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mcp.json"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_sarif_output_is_json_serializable():
    sarif = render_sarif(make_report())
    text = json.dumps(sarif)
    assert json.loads(text)["version"] == "2.1.0"


def test_sarif_rules_are_deduplicated_by_rule_id():
    finding_a = Finding(
        rule_id="MSC001", title="t", severity=Severity.HIGH, description="d",
        evidence="e", file="a.json", remediation="r",
    )
    finding_b = Finding(
        rule_id="MSC001", title="t", severity=Severity.HIGH, description="d",
        evidence="e", file="b.json", remediation="r",
    )
    report = Report(decision=Decision.WARN, risk_score=20, findings=[finding_a, finding_b])
    sarif = render_sarif(report)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert len(sarif["runs"][0]["results"]) == 2
