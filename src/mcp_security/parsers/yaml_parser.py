"""Safe YAML parsing and normalization of MCP configuration files.

Uses ``yaml.safe_load`` exclusively. Unsafe loaders (``yaml.load`` with the
default/full loader, or anything that can construct arbitrary Python
objects) are never used, since scanned repositories are untrusted input.
"""

from __future__ import annotations

from typing import List, Tuple

import yaml

from mcp_security.model.component import Component
from mcp_security.parsers.json_parser import _normalize_document, _validate_document_structure


def parse_yaml_file(content: str, relative_path: str) -> Tuple[List[Component], List[str]]:
    """Parse a YAML MCP config string into normalized Components.

    Mirrors :func:`mcp_security.parsers.json_parser.parse_json_file` in
    behavior: soft errors instead of exceptions, reuses the same
    normalization logic once the document is a plain dict.
    """
    errors: List[str] = []
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        errors.append(f"{relative_path}: malformed YAML ({exc})")
        return [], errors

    if data is None:
        errors.append(
            f"{relative_path}: empty YAML document; refusing to treat the config as clean"
        )
        return [], errors

    if not isinstance(data, dict):
        errors.append(f"{relative_path}: expected a YAML mapping at the top level, skipping")
        return [], errors

    errors.extend(_validate_document_structure(data, relative_path))
    components = _normalize_document(data, relative_path)
    return components, errors
