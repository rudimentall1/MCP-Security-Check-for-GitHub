"""MCP configuration discovery.

Identifies files that are *likely* MCP configuration based on common,
recognizable naming patterns. This is intentionally not exhaustive -- MCP
configuration is not standardized across every tool/client, and claiming
exhaustive coverage would be misleading.
"""

from __future__ import annotations

import os
from typing import List, Optional

from mcp_security.discovery.files import DEFAULT_MAX_FILE_SIZE_BYTES, DiscoveredFile, iter_candidate_files

# Exact filenames (case-sensitive) that are recognized MCP configuration.
KNOWN_MCP_FILENAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
}

# Suffix patterns for filenames within recognized directories, e.g.
# ".cursor/mcp.json", ".vscode/mcp.json".
KNOWN_MCP_RELATIVE_SUFFIXES = (
    os.path.join(".cursor", "mcp.json"),
    os.path.join(".vscode", "mcp.json"),
    os.path.join(".codeium", "mcp.json"),
)

# File extensions that are worth parsing at all (used to filter down the
# generic file walk before filename matching).
CANDIDATE_EXTENSIONS = {".json", ".yaml", ".yml"}


def is_likely_mcp_config(relative_path: str) -> bool:
    filename = os.path.basename(relative_path)
    if filename in KNOWN_MCP_FILENAMES:
        return True
    normalized = relative_path.replace("\\", "/")
    for suffix in KNOWN_MCP_RELATIVE_SUFFIXES:
        if normalized.endswith(suffix.replace("\\", "/")):
            return True
    return False


def discover_mcp_files(root: str, *, explicit_paths: Optional[List[str]] = None) -> List[DiscoveredFile]:
    """Return discovered MCP configuration files under ``root``.

    Args:
        root: Directory to scan.
        explicit_paths: Optional list of explicit file paths (relative to
            ``root`` or absolute) supplied via CLI/action input. These are
            always included (subject to the same size limit) regardless of
            whether their name matches a known pattern, since the caller
            has explicitly asked for them.
    """
    all_files = iter_candidate_files(root)
    matched = [f for f in all_files if is_likely_mcp_config(f.relative_path)]

    if explicit_paths:
        matched_paths = {f.path for f in matched}
        for p in explicit_paths:
            abs_path = p if os.path.isabs(p) else os.path.join(root, p)
            abs_path = os.path.abspath(abs_path)
            # Skip symlinks - they may point outside the scanned tree
            if os.path.islink(abs_path):
                continue
            if abs_path in matched_paths or not os.path.isfile(abs_path):
                continue
            size = os.path.getsize(abs_path)
            if size > DEFAULT_MAX_FILE_SIZE_BYTES:
                continue
            matched.append(
                DiscoveredFile(
                    path=abs_path,
                    relative_path=os.path.relpath(abs_path, os.path.abspath(root)),
                    size=size,
                )
            )
    return matched
