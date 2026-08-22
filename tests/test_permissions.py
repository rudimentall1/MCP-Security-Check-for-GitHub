from mcp_security.analyzers.permissions import base_severity_for, is_high_risk
from mcp_security.model.capability import Capability
from mcp_security.model.component import Component, ComponentKind
from mcp_security.model.finding import Severity
from mcp_security.rules import build_default_engine


def make_component(name, capabilities, raw=None, metadata=None):
    return Component(
        name=name,
        kind=ComponentKind.MCP_SERVER,
        source="local",
        file="mcp.json",
        capabilities=capabilities,
        raw=raw or {},
        metadata=metadata or {},
    )


def test_shell_execute_is_high_risk():
    assert is_high_risk("shell.execute")
    assert base_severity_for("shell.execute") == Severity.HIGH


def test_unknown_capability_is_not_high_risk():
    assert not is_high_risk("wallet.sign")
    assert base_severity_for("wallet.sign") == Severity.INFO


def test_msc001_fires_for_shell_execute():
    component = make_component("srv", [Capability("shell", "execute", target="local")])
    engine = build_default_engine()
    findings = engine.run([component])
    rule_ids = {f.rule_id for f in findings}
    assert "MSC001" in rule_ids


def test_msc006_fires_for_filesystem_write():
    component = make_component("srv", [Capability("filesystem", "write", target="workspace")])
    engine = build_default_engine()
    findings = engine.run([component])
    rule_ids = {f.rule_id for f in findings}
    assert "MSC006" in rule_ids


def test_msc009_fires_for_unrestricted_network():
    component = make_component("srv", [Capability("network", "unrestricted")])
    engine = build_default_engine()
    findings = engine.run([component])
    rule_ids = {f.rule_id for f in findings}
    assert "MSC009" in rule_ids


def test_safe_component_produces_no_findings():
    component = make_component(
        "srv",
        [Capability("filesystem", "read", target="workspace")],
        raw={"command": "srv"},
        metadata={"publisher": "Acme", "version": "1.0.0"},
    )
    engine = build_default_engine()
    findings = engine.run([component])
    assert findings == []


def test_findings_include_required_fields():
    component = make_component("srv", [Capability("shell", "execute", target="local")])
    engine = build_default_engine()
    findings = engine.run([component])
    assert findings
    f = findings[0]
    assert f.rule_id
    assert f.title
    assert f.severity in Severity
    assert f.description
    assert f.evidence
    assert f.file
    assert f.remediation
