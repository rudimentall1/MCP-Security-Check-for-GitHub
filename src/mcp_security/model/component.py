"""Normalized component model.

A Component represents anything that carries capabilities: an MCP server,
an MCP tool, an Agent Skill, a plugin, or an agent configuration. For the
MVP, MCP server/configuration is the primary component type produced by
the parsers, but the model is deliberately generic so Skills/Plugins can
be added later without changing downstream analyzers/rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from mcp_security.model.capability import Capability


class ComponentKind(str, Enum):
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    AGENT_SKILL = "agent_skill"
    PLUGIN = "plugin"
    AGENT_CONFIG = "agent_config"
    UNKNOWN = "unknown"


@dataclass
class Component:
    """A discovered, normalized unit of MCP/agent configuration."""

    name: str
    kind: ComponentKind
    source: str
    """Where the component came from, e.g. 'local', 'remote', 'npm', 'pip'."""
    file: str
    """Path (relative to scan root) of the file this component was parsed from."""
    capabilities: List[Capability] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Optional[Dict[str, Any]] = None
    """Original normalized dict, kept for debugging / provenance. Never executed."""

    def capability_ids(self) -> List[str]:
        return sorted({c.id for c in self.capabilities})

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self.capability_ids()
