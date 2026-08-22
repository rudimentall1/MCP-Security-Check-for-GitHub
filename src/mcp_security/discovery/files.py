"""Safe file discovery utilities.

This module only walks the filesystem and returns candidate file paths.
It never reads file content beyond a size check, never executes anything,
and never follows network URLs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, List

# Directories we never want to descend into: VCS internals, dependency
# trees, virtualenvs, build output. Scanning these would be slow, noisy,
# and largely irrelevant to *this repository's* MCP configuration.
DEFAULT_IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "site-packages",
}

# Refuse to read files larger than this. MCP configuration files are small
# JSON/YAML documents; anything huge is either not a config file or an
# attempt to exhaust memory/CPU during scanning.
DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MiB


@dataclass
class DiscoveredFile:
    path: str
    """Absolute path on disk."""
    relative_path: str
    """Path relative to the scan root, used in reports."""
    size: int


def iter_candidate_files(
    root: str,
    *,
    ignored_dirs: Iterable[str] = DEFAULT_IGNORED_DIRS,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> List[DiscoveredFile]:
    """Walk ``root`` and return files that are safe/small enough to inspect.

    Oversized files are skipped (not read) rather than raising, so a single
    huge unrelated file in a repository does not abort the whole scan.
    """
    root = os.path.abspath(root)
    ignored = set(ignored_dirs)
    results: List[DiscoveredFile] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignored and not d.startswith(".git")]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                continue
            if size > max_file_size:
                continue
            rel_path = os.path.relpath(full_path, root)
            results.append(DiscoveredFile(path=full_path, relative_path=rel_path, size=size))
    return results
