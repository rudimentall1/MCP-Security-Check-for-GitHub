from mcp_security.analyzers.capabilities import extract_capabilities
from mcp_security.model.component import Component, ComponentKind


def make_component(raw, metadata=None):
    return Component(
        name="test-server",
        kind=ComponentKind.MCP_SERVER,
        source="local",
        file="mcp.json",
        raw=raw,
        metadata=metadata or {},
    )


def test_shell_command_yields_shell_execute():
    component = make_component({"command": "bash", "args": ["-c", "echo hi"]})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "shell.execute" in ids


def test_external_url_yields_network_external():
    component = make_component({"command": None, "url": "https://api.example.com"})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "network.external" in ids


def test_localhost_url_yields_network_local_not_external():
    component = make_component({"command": None, "url": "http://localhost:9000"})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "network.local" in ids
    assert "network.external" not in ids


def test_secret_like_env_var_yields_secrets_read():
    component = make_component({"command": "srv", "env": {"MY_API_TOKEN": "${MY_API_TOKEN}"}})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "secrets.read" in ids


def test_non_secret_env_var_does_not_yield_secrets_read():
    component = make_component({"command": "srv", "env": {"LOG_LEVEL": "debug"}})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "secrets.read" not in ids


def test_write_tool_name_yields_filesystem_write():
    component = make_component({"command": "srv", "tools": ["write_file"]})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "filesystem.write" in ids


def test_unrecognized_permission_string_is_not_translated():
    component = make_component({"command": "srv", "permissions": ["totally-made-up-permission"]})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    # Unknown data must not become a capability / must not be assumed dangerous.
    assert not any("totally-made-up" in cid for cid in ids)


def test_dotted_permission_string_is_translated():
    component = make_component({"command": "srv", "permissions": ["filesystem.delete"]})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "filesystem.delete" in ids


def test_local_command_implies_filesystem_read_workspace():
    component = make_component({"command": "srv", "args": []})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "filesystem.read" in ids


def test_remote_url_only_component_does_not_imply_filesystem_read():
    component = make_component({"command": None, "url": "https://api.example.com"})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "filesystem.read" not in ids


def test_package_manager_install_token_yields_package_install():
    component = make_component({"command": "npm", "args": ["install", "some-pkg"]})
    caps = extract_capabilities(component)
    ids = {c.id for c in caps}
    assert "package.install" in ids


def test_capabilities_are_deduplicated():
    component = make_component({"command": "bash", "args": ["-c", "bash -c echo"]})
    caps = extract_capabilities(component)
    shell_caps = [c for c in caps if c.id == "shell.execute"]
    # Same id + same target (local) should be deduplicated to one entry.
    assert len(shell_caps) == 1
