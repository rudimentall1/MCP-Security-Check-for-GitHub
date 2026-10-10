"""Safe JSON parsing and normalization of MCP configuration files.

Only ``json.loads`` (stdlib) is used -- no ``eval``, no custom object
hooks that could execute code. Malformed JSON is reported as a soft error,
never raised to the caller as a crash.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from mcp_security.model.component import Component, ComponentKind

# Keys under which one or more MCP server definitions are commonly nested.
SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "mcp_servers")


def parse_json_file(content: str, relative_path: str) -> Tuple[List[Component], List[str]]:
    """Parse a JSON MCP config string into normalized Components.

    Returns a ``(components, errors)`` tuple. Errors are human-readable
    strings describing what went wrong; parsing continues best-effort
    rather than aborting the whole scan.
    """
    errors: List[str] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        errors.append(f"{relative_path}: malformed JSON ({exc.msg} at line {exc.lineno})")
        return [], errors

    if not isinstance(data, dict):
        errors.append(f"{relative_path}: expected a JSON object at the top level, skipping")
        return [], errors

    errors.extend(_validate_document_structure(data, relative_path))
    components = _normalize_document(data, relative_path)
    return components, errors


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
        return errors

    # A direct, single-server document is also a supported shape.
    if any(k in data for k in ("command", "url", "args", "tools", "permissions")):
        return errors

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
        "command": server_def.get("command"),
        "args": server_def.get("args") if isinstance(server_def.get("args"), list) else [],
        "env": server_def.get("env") if isinstance(server_def.get("env"), dict) else {},
        "url": server_def.get("url"),
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
