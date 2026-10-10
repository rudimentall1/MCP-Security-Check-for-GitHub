"""Safe YAML parsing and normalization of MCP configuration files.

Uses a SafeLoader subclass exclusively. Duplicate explicit mapping keys are
rejected because silently accepting the last value can hide dangerous settings.
YAML merge keys, anchors, and aliases remain supported.
"""

from __future__ import annotations

from typing import List, Tuple

import yaml

from mcp_security.model.component import Component
from mcp_security.parsers.json_parser import _normalize_document, _validate_document_structure


class DuplicateYAMLKeyError(yaml.YAMLError):
    """Raised when a YAML mapping repeats an explicit key."""


class _DuplicateKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate explicit keys without rejecting merges."""

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.nodes.MappingNode):
            explicit_keys = set()
            for key_node, _value_node in node.value:
                # Merge keys intentionally import mappings and can be overridden
                # by explicit keys; only reject duplicate keys written directly.
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in explicit_keys
                    explicit_keys.add(key)
                except TypeError:
                    # Let SafeLoader produce its normal error for unhashable keys.
                    continue
                if duplicate:
                    raise DuplicateYAMLKeyError(
                        "duplicate YAML mapping key; refusing ambiguous configuration"
                    )
        return super().construct_mapping(node, deep=deep)


def parse_yaml_file(content: str, relative_path: str) -> Tuple[List[Component], List[str]]:
    """Parse a YAML MCP config string into normalized Components.

    Mirrors :func:`mcp_security.parsers.json_parser.parse_json_file` in
    behavior: soft errors instead of exceptions, reuses the same
    normalization logic once the document is a plain dict.
    """
    errors: List[str] = []
    try:
        data = yaml.load(content, Loader=_DuplicateKeySafeLoader)
    except DuplicateYAMLKeyError:
        errors.append(
            f"{relative_path}: duplicate YAML mapping key; refusing to analyze an ambiguous configuration"
        )
        return [], errors
    except yaml.YAMLError:
        # Do not include parser exception details: PyYAML may echo source lines
        # that contain credentials or other secrets.
        errors.append(f"{relative_path}: malformed YAML; refusing to analyze the configuration")
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
