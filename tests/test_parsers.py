from mcp_security.parsers.json_parser import parse_json_file
from mcp_security.parsers.yaml_parser import parse_yaml_file
import json


def test_parse_json_file_extracts_server_from_mcpServers():
    content = """
    {
      "mcpServers": {
        "my-server": {
          "command": "my-mcp-server",
          "args": ["--flag"]
        }
      }
    }
    """
    components, errors = parse_json_file(content, "mcp.json")
    assert errors == []
    assert len(components) == 1
    assert components[0].name == "my-server"
    assert components[0].raw["command"] == "my-mcp-server"


def test_parse_json_file_extracts_top_level_single_server():
    content = '{"command": "solo-server", "args": []}'
    components, errors = parse_json_file(content, "mcp.json")
    assert errors == []
    assert len(components) == 1


def test_parse_json_file_malformed_json_returns_soft_error():
    content = "{not valid json"
    components, errors = parse_json_file(content, "mcp.json")
    assert components == []
    assert len(errors) == 1
    assert "malformed JSON" in errors[0]


def test_parse_json_file_non_object_top_level():
    content = "[1, 2, 3]"
    components, errors = parse_json_file(content, "mcp.json")
    assert components == []
    assert len(errors) == 1


def test_parse_json_file_unknown_fields_do_not_crash_or_flag():
    content = """
    {
      "mcpServers": {
        "srv": {
          "command": "srv-bin",
          "totallyUnknownField": {"nested": "value"},
          "anotherUnknown": [1, 2, 3]
        }
      }
    }
    """
    components, errors = parse_json_file(content, "mcp.json")
    assert errors == []
    assert len(components) == 1
    # Unknown fields must not be silently promoted into capabilities/metadata risk.
    assert "totallyUnknownField" not in components[0].raw


def test_parse_yaml_file_safe_load():
    content = """
    mcpServers:
      yaml-server:
        command: yaml-mcp-server
        args:
          - "--x"
    """
    components, errors = parse_yaml_file(content, "mcp.yaml")
    assert errors == []
    assert len(components) == 1
    assert components[0].name == "yaml-server"


def test_parse_yaml_file_malformed_returns_soft_error():
    content = "mcpServers: [unbalanced"
    components, errors = parse_yaml_file(content, "mcp.yaml")
    assert components == []
    assert len(errors) == 1
    assert "malformed YAML" in errors[0]


def test_parse_yaml_file_empty_document_fails_closed():
    components, errors = parse_yaml_file("", "mcp.yaml")
    assert components == []
    assert len(errors) == 1
    assert "empty YAML document" in errors[0]


def test_parse_yaml_file_does_not_use_unsafe_constructors():
    # A YAML document attempting to use a Python-object tag must not be
    # constructed as that object -- safe_load should reject/ignore it.
    content = "mcpServers: !!python/object:os.system {}"
    components, errors = parse_yaml_file(content, "mcp.yaml")
    assert components == []
    assert len(errors) == 1


def test_parse_yaml_file_supports_anchors_and_aliases():
    content = """
    common: &common
      publisher: Acme
      version: "1.0.0"
    mcpServers:
      srv:
        <<: *common
        command: srv-bin
    """
    components, errors = parse_yaml_file(content, "mcp.yaml")
    assert errors == []
    assert len(components) == 1
    assert components[0].metadata["publisher"] == "Acme"


def test_parse_json_file_handles_null_and_unexpected_field_types():
    content = json.dumps(
        {
            "mcpServers": {
                "srv": {
                    "command": "srv-bin",
                    "args": None,
                    "env": None,
                    "tools": "not-a-list",
                    "permissions": 42,
                }
            }
        }
    )
    components, errors = parse_json_file(content, "mcp.json")
    assert len(errors) == 2
    assert any("field 'tools' must be a list" in e for e in errors)
    assert any("field 'permissions' must be a list or mapping" in e for e in errors)
    assert len(components) == 1
    # Null optional args/env are normalized to empty defaults; invalid declared
    # tools/permissions types are also reported so the scan cannot look clean.
    assert components[0].raw["args"] == []
    assert components[0].raw["env"] == {}
    assert components[0].raw["tools"] == []
    assert components[0].raw["permissions"] is None



def test_parse_json_file_wrong_server_container_type_returns_error():
    components, errors = parse_json_file('{"mcpServers": []}', "mcp.json")
    assert components == []
    assert any("expected 'mcpServers' to be an object/mapping" in e for e in errors)


def test_parse_json_file_wrong_server_entry_type_returns_error():
    components, errors = parse_json_file('{"mcpServers": {"srv": "bash"}}', "mcp.json")
    assert components == []
    assert any("MCP server 'srv'" in e and "object/mapping" in e for e in errors)


def test_parse_json_file_without_recognizable_server_structure_returns_error():
    components, errors = parse_json_file('{"unknown": {"command": "bash"}}', "mcp.json")
    assert components == []
    assert any("no recognizable MCP server definition" in e for e in errors)


def test_parse_yaml_file_wrong_server_container_type_returns_error():
    components, errors = parse_yaml_file("mcpServers: []", "mcp.yaml")
    assert components == []
    assert any("expected 'mcpServers' to be an object/mapping" in e for e in errors)


def test_parse_yaml_file_without_recognizable_server_structure_returns_error():
    components, errors = parse_yaml_file("settings: {}", "mcp.yaml")
    assert components == []
    assert any("no recognizable MCP server definition" in e for e in errors)



def test_json_server_definition_without_command_or_url_returns_error():
    components, errors = parse_json_file(
        '{"mcpServers": {"srv": {"tools": ["run_shell"]}}}', "mcp.json"
    )
    assert len(components) == 1
    assert any("must define a non-empty string 'command' or 'url'" in e for e in errors)


def test_json_non_string_command_returns_error():
    components, errors = parse_json_file(
        '{"mcpServers": {"srv": {"command": ["bash"]}}}', "mcp.json"
    )
    assert len(components) == 1
    assert any("field 'command' must be a string" in e for e in errors)


def test_yaml_server_definition_without_command_or_url_returns_error():
    from mcp_security.parsers.yaml_parser import parse_yaml_file

    components, errors = parse_yaml_file(
        "mcpServers:\n  srv:\n    tools: [run_shell]\n", "mcp.yaml"
    )
    assert len(components) == 1
    assert any("must define a non-empty string 'command' or 'url'" in e for e in errors)
