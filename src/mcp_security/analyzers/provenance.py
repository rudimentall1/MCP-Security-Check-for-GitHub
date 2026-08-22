"""Basic offline trust/provenance signals.

This is deliberately minimal for v0.1: it only inspects information already
present locally (no network calls). It must never be presented as proof
that a component is trustworthy -- only as informational signals that
*reduce confidence* when absent, separate from security risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from mcp_security.model.component import Component


@dataclass
class ProvenanceSignal:
    name: str
    present: bool
    note: str


def evaluate_provenance(component: Component) -> List[ProvenanceSignal]:
    raw = component.raw or {}
    metadata = component.metadata or {}
    signals: List[ProvenanceSignal] = []

    signals.append(
        ProvenanceSignal(
            name="source_locality",
            present=component.source == "local",
            note="Component is launched from a local command" if component.source == "local"
            else "Component is fetched from a remote URL",
        )
    )

    publisher = metadata.get("publisher")
    signals.append(
        ProvenanceSignal(
            name="publisher_declared",
            present=bool(publisher),
            note=f"Publisher declared: {publisher}" if publisher else "No publisher metadata declared",
        )
    )

    version = metadata.get("version")
    pinned = bool(version) and version not in ("latest", "*")
    signals.append(
        ProvenanceSignal(
            name="version_pinned",
            present=pinned,
            note=f"Version pinned: {version}" if pinned else "No pinned version declared (or uses 'latest')",
        )
    )

    return signals
