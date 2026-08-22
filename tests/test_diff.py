from mcp_security.diff.capability_diff import diff_components
from mcp_security.model.capability import Capability
from mcp_security.model.component import Component, ComponentKind


def make_component(capabilities):
    return Component(
        name="srv",
        kind=ComponentKind.MCP_SERVER,
        source="local",
        file="mcp.json",
        capabilities=capabilities,
    )


def test_diff_detects_added_capabilities():
    base = [make_component([Capability("filesystem", "read")])]
    head = [
        make_component(
            [
                Capability("filesystem", "read"),
                Capability("filesystem", "write"),
                Capability("shell", "execute"),
            ]
        )
    ]
    summary, findings = diff_components(base, head)
    assert set(summary.added) == {"filesystem.write", "shell.execute"}
    assert summary.removed == []


def test_diff_detects_removed_capabilities():
    base = [make_component([Capability("filesystem", "read"), Capability("network", "external")])]
    head = [make_component([Capability("filesystem", "read")])]
    summary, findings = diff_components(base, head)
    assert summary.removed == ["network.external"]
    assert summary.added == []


def test_diff_detects_unchanged_capabilities():
    base = [make_component([Capability("filesystem", "read", target="workspace")])]
    head = [make_component([Capability("filesystem", "read", target="workspace")])]
    summary, findings = diff_components(base, head)
    assert summary.unchanged == ["filesystem.read"]
    assert summary.changed == []


def test_diff_detects_changed_target_as_drift():
    base = [make_component([Capability("filesystem", "write", target="workspace")])]
    head = [make_component([Capability("filesystem", "write", target="/")])]
    summary, findings = diff_components(base, head)
    assert summary.changed == [{"capability": "filesystem.write", "before_target": "workspace", "after_target": "/"}]
    rule_ids = {f.rule_id for f in findings}
    assert "MSC020" in rule_ids


def test_diff_new_high_risk_capability_triggers_msc015():
    base = [make_component([])]
    head = [make_component([Capability("shell", "execute")])]
    summary, findings = diff_components(base, head)
    rule_ids = {f.rule_id for f in findings}
    assert "MSC015" in rule_ids


def test_diff_low_risk_new_capability_does_not_trigger_msc015():
    base = [make_component([])]
    head = [make_component([Capability("filesystem", "read")])]
    summary, findings = diff_components(base, head)
    rule_ids = {f.rule_id for f in findings}
    assert "MSC015" not in rule_ids


def test_diff_new_external_endpoint_triggers_msc018():
    base = [make_component([])]
    head = [make_component([Capability("network", "external", target="https://new.example.com")])]
    summary, findings = diff_components(base, head)
    rule_ids = {f.rule_id for f in findings}
    assert "MSC018" in rule_ids


def test_diff_no_changes_produces_no_findings():
    base = [make_component([Capability("filesystem", "read")])]
    head = [make_component([Capability("filesystem", "read")])]
    summary, findings = diff_components(base, head)
    assert findings == []
