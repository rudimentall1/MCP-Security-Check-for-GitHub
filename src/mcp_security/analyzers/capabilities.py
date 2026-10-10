"""Capability extraction.

Turns a normalized :class:`Component` (produced by the parsers) into a list
of :class:`Capability` objects. This is heuristic by nature -- MCP
configuration does not universally declare a machine-readable capability
list, so we infer capabilities from command names, arguments, declared
tools, and explicit permission blocks when present.

Mandatory principle: unknown/unrecognized data is simply not translated
into a capability. It must never be treated as automatically dangerous.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List
from urllib.parse import urlsplit

from mcp_security.model.capability import Capability
from mcp_security.model.component import Component

# Command/binary names that imply shell.execute when used as the launcher
# or appear as an argument token (e.g. "sh -c", "bash -c").
SHELL_INDICATORS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

# Command/binary names that imply dynamic code execution.
CODE_EXEC_INDICATORS = {"python", "python3", "node", "ruby", "perl", "eval"}

# Package manager commands that imply package.install.
PACKAGE_INSTALL_INDICATORS = {"pip", "pip3", "npm", "npx", "yarn", "pnpm", "cargo", "gem"}

# Explicit "install" style subcommands/flags, used alongside the above.
INSTALL_TOKENS = {"install", "add", "i"}

# Well-known environment variable name fragments that indicate secret/
# credential material is being read by the component.
SECRET_ENV_PATTERNS = (
    re.compile(r"(?i)token"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)api[_-]?key"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)credential"),
    re.compile(r"(?i)auth"),
)

# Permission-string -> capability mapping for explicit "permissions" blocks.
PERMISSION_STRING_MAP: Dict[str, str] = {
    "filesystem:read": "filesystem.read",
    "filesystem:write": "filesystem.write",
    "filesystem:delete": "filesystem.delete",
    "shell:execute": "shell.execute",
    "network:local": "network.local",
    "network:external": "network.external",
    "network:unrestricted": "network.unrestricted",
    "secrets:read": "secrets.read",
    "credentials:read": "credentials.read",
    "env:read": "environment.read",
    "github:read": "github.read",
    "github:write": "github.write",
    "github:admin": "github.admin",
}


def extract_capabilities(component: Component) -> List[Capability]:
    """Return the list of capabilities inferred for ``component``.

    Does not mutate ``component``; the caller is responsible for assigning
    the result back to ``component.capabilities``.
    """
    raw = component.raw or {}
    capabilities: List[Capability] = []

    capabilities.extend(_from_command_and_args(raw))
    capabilities.extend(_from_url(raw))
    capabilities.extend(_from_env(raw))
    capabilities.extend(_from_tools(raw))
    capabilities.extend(_from_permissions(raw))

    # Deduplicate while preserving order (same id + target).
    seen = set()
    deduped: List[Capability] = []
    for cap in capabilities:
        key = (cap.id, cap.target)
        if key not in seen:
            seen.add(key)
            deduped.append(cap)
    return deduped


def _tokenize_command(raw: Dict) -> List[str]:
    command = raw.get("command")
    args = raw.get("args") or []
    tokens: List[str] = []
    if isinstance(command, str):
        tokens.append(command)
    if isinstance(args, list):
        tokens.extend(str(a) for a in args)
    return tokens


def _basename(token: str) -> str:
    return token.replace("\\", "/").split("/")[-1].lower()


def _from_command_and_args(raw: Dict) -> List[Capability]:
    caps: List[Capability] = []
    tokens = _tokenize_command(raw)
    basenames = [_basename(t) for t in tokens]

    if any(b in SHELL_INDICATORS for b in basenames):
        caps.append(Capability("shell", "execute", target="local"))

    if any(b in CODE_EXEC_INDICATORS for b in basenames):
        caps.append(Capability("code", "execute", target="local"))

    if any(b in PACKAGE_INSTALL_INDICATORS for b in basenames):
        if any(t.lower() in INSTALL_TOKENS for t in tokens):
            caps.append(Capability("package", "install"))
        else:
            caps.append(Capability("package", "execute"))

    # A local filesystem-backed MCP server process is, at minimum,
    # implicitly able to read its working directory. We only infer this
    # for servers launched via a local command (not remote/url-based).
    if raw.get("command") and not raw.get("url"):
        caps.append(Capability("filesystem", "read", target="workspace"))

    return caps


def _from_url(raw: Dict) -> List[Capability]:
    url = raw.get("url")
    if not isinstance(url, str) or not url:
        return []
    if not url.lower().startswith(("http://", "https://")):
        return []

    # Classify by the parsed hostname, never by substring: an attacker-controlled
    # host such as localhost.attacker.example must remain external.
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        hostname = None
    normalized_host = (hostname or "").rstrip(".").lower()
    is_local = normalized_host == "localhost" or normalized_host.endswith(".localhost")
    if not is_local and normalized_host:
        try:
            is_local = ipaddress.ip_address(normalized_host).is_loopback
        except ValueError:
            pass

    if is_local:
        return [Capability("network", "local", target=url)]
    return [Capability("network", "external", target=url)]


def _from_env(raw: Dict) -> List[Capability]:
    env = raw.get("env") or {}
    caps: List[Capability] = []
    if not isinstance(env, dict):
        return caps
    for key in env.keys():
        if any(pattern.search(str(key)) for pattern in SECRET_ENV_PATTERNS):
            caps.append(Capability("secrets", "read", target=str(key)))
    return caps


def _from_tools(raw: Dict) -> List[Capability]:
    tools = raw.get("tools") or []
    caps: List[Capability] = []
    if not isinstance(tools, list):
        return caps
    for tool in tools:
        tool_name = tool if isinstance(tool, str) else (tool.get("name") if isinstance(tool, dict) else None)
        if not tool_name:
            continue
        lowered = str(tool_name).lower()
        if any(k in lowered for k in ("shell", "exec", "command", "run")):
            caps.append(Capability("shell", "execute", target=str(tool_name)))
        if any(k in lowered for k in ("browser", "navigate")):
            caps.append(Capability("browser", "navigate", target=str(tool_name)))
        if "download" in lowered:
            caps.append(Capability("browser", "download", target=str(tool_name)))
        if any(k in lowered for k in ("write_file", "writefile", "file_write")):
            caps.append(Capability("filesystem", "write", target=str(tool_name)))
        if any(k in lowered for k in ("delete_file", "deletefile", "file_delete", "rm")):
            caps.append(Capability("filesystem", "delete", target=str(tool_name)))
    return caps


def _from_permissions(raw: Dict) -> List[Capability]:
    permissions = raw.get("permissions")
    caps: List[Capability] = []
    if permissions is None:
        return caps

    entries: List[str] = []
    if isinstance(permissions, list):
        entries = [str(p) for p in permissions]
    elif isinstance(permissions, dict):
        for key, value in permissions.items():
            if value:
                entries.append(str(key))

    for entry in entries:
        normalized = entry.strip().lower()
        mapped = PERMISSION_STRING_MAP.get(normalized)
        if mapped:
            type_, action = mapped.split(".", 1)
            caps.append(Capability(type_, action, target="declared"))
        elif "." in normalized:
            # Already looks like a dotted capability id, e.g. "filesystem.write".
            type_, _, action = normalized.partition(".")
            caps.append(Capability(type_, action, target="declared"))
        # Unrecognized permission strings are intentionally NOT translated
        # into a capability -- unknown data must not be treated as
        # automatically dangerous.
    return caps
