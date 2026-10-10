"""Safe JSON parsing and normalization of MCP configuration files.

Only ``json.loads`` (stdlib) is used -- no ``eval``, no custom object
hooks that could execute code. Malformed JSON is reported as a soft error,
never raised to the caller as a crash.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from mcp_security.model.component import Component, ComponentKind

# Keys under which one or more MCP server definitions are commonly nested.
SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "mcp_servers")


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object contains a repeated key."""


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build a JSON object only when every key is unique."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Do not include the key itself; config keys can contain sensitive data.
            raise DuplicateJSONKeyError("duplicate object key")
        result[key] = value
    return result


def parse_json_file(content: str, relative_path: str) -> Tuple[List[Component], List[str]]:
    """Parse a JSON MCP config string into normalized Components.

    Returns a ``(components, errors)`` tuple. Errors are human-readable
    strings describing what went wrong; parsing continues best-effort
    rather than aborting the whole scan.
    """
    errors: List[str] = []
    try:
        data = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except DuplicateJSONKeyError:
        errors.append(
            f"{relative_path}: duplicate JSON object key; refusing to analyze an ambiguous configuration"
        )
        return [], errors
    except json.JSONDecodeError as exc:
        errors.append(f"{relative_path}: malformed JSON ({exc.msg} at line {exc.lineno})")
        return [], errors

    if not isinstance(data, dict):
        errors.append(f"{relative_path}: expected a JSON object at the top level, skipping")
        return [], errors

    errors.extend(_validate_document_structure(data, relative_path))
    components = _normalize_document(data, relative_path)
    return components, errors


def _validate_server_definition(
    server_def: Dict[str, Any], name: str, relative_path: str
) -> List[str]:
    """Validate fields whose malformed types could hide security-relevant data."""
    errors: List[str] = []
    command = server_def.get("command")
    url = server_def.get("url")

    if command is not None and not isinstance(command, str):
        errors.append(
            f"{relative_path}: MCP server '{name}' field 'command' must be a string"
        )
    if url is not None and not isinstance(url, str):
        errors.append(
            f"{relative_path}: MCP server '{name}' field 'url' must be a string"
        )

    if isinstance(url, str) and url.strip():
        try:
            parsed_url = urlsplit(url.strip())
            valid_http_url = (
                parsed_url.scheme.lower() in {"http", "https"}
                and bool(parsed_url.hostname)
            )
            # Accessing .port also validates malformed/out-of-range ports.
            _ = parsed_url.port
        except ValueError:
            valid_http_url = False
        if not valid_http_url:
            errors.append(
                f"{relative_path}: MCP server '{name}' field 'url' must be a "
                "valid absolute HTTP(S) URL with a hostname"
            )

    has_command = isinstance(command, str) and bool(command.strip())
    has_url = isinstance(url, str) and bool(url.strip())
    if not has_command and not has_url:
        errors.append(
            f"{relative_path}: MCP server '{name}' must define a non-empty "
            "string 'command' or 'url'"
        )

    for field, expected, allow_null in (
        ("args", list, True),
        ("env", dict, True),
        ("tools", list, True),
        ("headers", dict, True),
    ):
        value = server_def.get(field)
        if value is None and allow_null:
            continue
        if not isinstance(value, expected):
            errors.append(
                f"{relative_path}: MCP server '{name}' field '{field}' "
                f"must be a {expected.__name__}"
            )

    permissions = server_def.get("permissions")
    if permissions is not None and not isinstance(permissions, (list, dict)):
        errors.append(
            f"{relative_path}: MCP server '{name}' field 'permissions' "
            "must be a list or mapping"
        )

    return errors


def _validate_document_structure(data: Dict[str, Any], relative_path: str) -> List[str]:
    """Report recognized MCP config documents that cannot be normalized safely."""
    errors: List[str] = []
    present_containers = [key for key in SERVER_CONTAINER_KEYS if key in data]

    if present_containers:
        for key in present_containers:
            container = data[key]
            if not isinstance(container, dict):
                errors.append(
                    f"{relative_path}: expected '{key}' to be an object/mapping; "
                    "MCP server definitions could not be inspected"
                )
                continue
            for name, server_def in container.items():
                if not isinstance(server_def, dict):
                    errors.append(
                        f"{relative_path}: MCP server '{name}' under '{key}' "
                        "must be an object/mapping"
                    )
                    continue
                errors.extend(_validate_server_definition(server_def, str(name), relative_path))
        return errors

    # A direct, single-server document is also a supported shape.
    if any(k in data for k in ("command", "url", "args", "env", "tools", "permissions")):
        direct_name = str(data.get("name") or _infer_name_from_path(relative_path))
        return _validate_server_definition(data, direct_name, relative_path)

    errors.append(
        f"{relative_path}: no recognizable MCP server definition or server "
        "container found; refusing to treat the config as clean"
    )
    return errors


def _normalize_document(data: Dict[str, Any], relative_path: str) -> List[Component]:
    components: List[Component] = []

    found_container = False
    for key in SERVER_CONTAINER_KEYS:
        container = data.get(key)
        if isinstance(container, dict):
            found_container = True
            for name, server_def in container.items():
                if isinstance(server_def, dict):
                    components.append(_build_server_component(name, server_def, relative_path))

    if not found_container:
        # Some configs describe a single server directly at the top level,
        # e.g. { "command": "...", "args": [...] }.
        if any(k in data for k in ("command", "url", "args", "tools", "permissions")):
            name = data.get("name") or _infer_name_from_path(relative_path)
            components.append(_build_server_component(name, data, relative_path))

    return components


def _build_server_component(name: str, server_def: Dict[str, Any], relative_path: str) -> Component:
    normalized = {
        "type": server_def.get("type"),
        "command": server_def.get("command"),
        "args": server_def.get("args") if isinstance(server_def.get("args"), list) else [],
        "env": server_def.get("env") if isinstance(server_def.get("env"), dict) else {},
        "url": server_def.get("url"),
        "headers": server_def.get("headers") if isinstance(server_def.get("headers"), dict) else {},
        "tools": server_def.get("tools") if isinstance(server_def.get("tools"), list) else [],
        "permissions": server_def.get("permissions")
        if isinstance(server_def.get("permissions"), (list, dict))
        else None,
    }
    metadata = {
        "publisher": server_def.get("publisher"),
        "version": server_def.get("version"),
        "description": server_def.get("description"),
    }
    return Component(
        name=str(name),
        kind=ComponentKind.MCP_SERVER,
        source="remote" if normalized["url"] else "local",
        file=relative_path,
        capabilities=[],
        metadata=metadata,
        raw=normalized,
    )


def _infer_name_from_path(relative_path: str) -> str:
    base = relative_path.replace("\\", "/").split("/")[-1]
    return base or "unnamed-server"
