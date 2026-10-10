"""MCP configuration discovery.

Identifies files that are *likely* MCP configuration based on common,
recognizable naming patterns. This is intentionally not exhaustive -- MCP
configuration is not standardized across every tool/client, and claiming
exhaustive coverage would be misleading.
"""

from __future__ import annotations

import os
from typing import List, Optional

from mcp_security.discovery.files import (
    DEFAULT_IGNORED_DIRS,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DiscoveredFile,
    iter_candidate_files,
)

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


def _validate_mcp_discovery(root: str) -> None:
    """Reject known MCP configs or directory entries that cannot be inspected.

    The generic file iterator intentionally skips oversized/unrelated files.
    For recognizable MCP config paths, silently skipping a symlink, stat error,
    or size-limit violation could turn an incomplete assessment into ALLOW.
    """
    root = os.path.abspath(root)
    if not os.path.exists(root):
        raise FileNotFoundError(f"scan root does not exist: {root}")
    if not os.path.isdir(root):
        raise NotADirectoryError(f"scan root is not a directory: {root}")
    if os.path.islink(root):
        raise ValueError(f"scan root is a symlink: {root}")

    ignored = set(DEFAULT_IGNORED_DIRS)

    def raise_walk_error(error: OSError) -> None:
        raise error

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=raise_walk_error
    ):
        kept_dirs = []
        for dirname in dirnames:
            if dirname in ignored or dirname.startswith(".git"):
                continue
            dir_path = os.path.join(dirpath, dirname)
            if os.path.islink(dir_path):
                relative = os.path.relpath(dir_path, root)
                raise ValueError(
                    f"directory symlink prevents complete MCP config discovery: {relative}"
                )
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            relative = os.path.relpath(file_path, root)
            if not is_likely_mcp_config(relative):
                continue
            if os.path.islink(file_path):
                raise ValueError(f"MCP config path is a symlink and was not scanned: {relative}")
            if not os.path.isfile(file_path):
                raise ValueError(f"MCP config path is not a regular file: {relative}")
            try:
                size = os.path.getsize(file_path)
            except OSError as exc:
                raise OSError(f"could not inspect MCP config file {relative}: {exc}") from exc
            if size > DEFAULT_MAX_FILE_SIZE_BYTES:
                raise ValueError(
                    f"MCP config exceeds the {DEFAULT_MAX_FILE_SIZE_BYTES}-byte limit: {relative}"
                )


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
    _validate_mcp_discovery(root)
    all_files = iter_candidate_files(root)
    matched = [f for f in all_files if is_likely_mcp_config(f.relative_path)]

    if explicit_paths:
        matched_paths = {f.path for f in matched}
        for p in explicit_paths:
            abs_path = p if os.path.isabs(p) else os.path.join(root, p)
            abs_path = os.path.abspath(abs_path)
            # Explicit paths are user intent: silently skipping a missing,
            # symlinked, or oversized file could make a partial scan look clean.
            if os.path.islink(abs_path):
                raise ValueError(f"explicit MCP config path is a symlink: {p}")
            if not os.path.isfile(abs_path):
                raise FileNotFoundError(f"explicit MCP config file not found: {p}")
            if abs_path in matched_paths:
                continue
            size = os.path.getsize(abs_path)
            if size > DEFAULT_MAX_FILE_SIZE_BYTES:
                raise ValueError(
                    f"explicit MCP config file exceeds the {DEFAULT_MAX_FILE_SIZE_BYTES}-byte limit: {p}"
                )
            matched.append(
                DiscoveredFile(
                    path=abs_path,
                    relative_path=os.path.relpath(abs_path, os.path.abspath(root)),
                    size=size,
                )
            )
            matched_paths.add(abs_path)
    return matched
