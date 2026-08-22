"""Placeholder for Agent Skill (SKILL.md) parsing.

Not implemented in the v0.1 MVP -- see README roadmap (v0.2: SKILL.md
analysis). Kept as a stub so the module layout does not need to change
when this is implemented, and so callers can detect "not yet supported"
explicitly rather than silently skipping skill files.
"""

from __future__ import annotations

from typing import List, Tuple

from mcp_security.model.component import Component


def parse_skill_file(content: str, relative_path: str) -> Tuple[List[Component], List[str]]:
    """Not implemented. Always returns no components and an info message."""
    return [], [f"{relative_path}: SKILL.md analysis is not implemented in v0.1 (planned for v0.2)"]
