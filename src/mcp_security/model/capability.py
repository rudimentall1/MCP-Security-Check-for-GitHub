"""Normalized capability model.

A Capability represents a single, atomic thing a component (MCP server,
tool, skill, plugin...) is able to do. Capabilities are expressed as
``type.action`` pairs (e.g. ``filesystem.write``, ``shell.execute``) with
an optional free-form ``target`` for extra context.

The model is intentionally string-based for ``type``/``action`` rather than
a closed enum so that new capability families (e.g. future Web3 capabilities
such as ``wallet.sign``) can be represented without changing this module.
``CapabilityType`` below only lists the *known* families used by the rule
engine; unknown types are still valid and simply won't match type-specific
rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class CapabilityType(str, Enum):
    """Well-known capability families.

    This list is not exhaustive by design. Unknown/未来 capability types
    are still accepted by :class:`Capability` -- they simply won't be
    recognized by type-specific rules until support is added.
    """

    FILESYSTEM = "filesystem"
    SHELL = "shell"
    NETWORK = "network"
    SECRETS = "secrets"
    CREDENTIALS = "credentials"
    ENVIRONMENT = "environment"
    GITHUB = "github"
    PACKAGE = "package"
    BROWSER = "browser"
    CODE = "code"
    # Reserved for future use - not a primary MVP feature.
    WALLET = "wallet"
    TRANSACTION = "transaction"
    CONTRACT = "contract"
    TOKEN = "token"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Capability:
    """A single normalized capability.

    Attributes:
        type: The capability family, e.g. "filesystem", "shell", "network".
            Free-form string; compare against :class:`CapabilityType` values
            for known families.
        action: The action within that family, e.g. "read", "write",
            "execute".
        target: Optional free-form context about scope, e.g. "workspace",
            "external", "unrestricted". Not all capabilities need a target.
        metadata: Optional extra data preserved for provenance/debugging.
            Never used to change security semantics on its own.
    """

    type: str
    action: str
    target: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable dotted identifier, e.g. ``filesystem.write``."""
        return f"{self.type}.{self.action}"

    def with_target(self, target: Optional[str]) -> "Capability":
        return Capability(type=self.type, action=self.action, target=target, metadata=self.metadata)

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.target:
            return f"{self.id} ({self.target})"
        return self.id

    def key(self) -> str:
        """Identity key used for diffing/deduplication.

        Two capabilities are considered "the same" for diff purposes when
        their type+action match, regardless of target/metadata. Target
        changes are reported separately as "changed" rather than
        added+removed.
        """
        return self.id
