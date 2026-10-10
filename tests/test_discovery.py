import os
import tempfile

import pytest

from mcp_security.discovery.files import DEFAULT_MAX_FILE_SIZE_BYTES, iter_candidate_files
from mcp_security.discovery.mcp import discover_mcp_files, is_likely_mcp_config


def test_is_likely_mcp_config_matches_known_filenames():
    assert is_likely_mcp_config(".mcp.json")
    assert is_likely_mcp_config("mcp.json")
    assert is_likely_mcp_config("claude_desktop_config.json")
    assert is_likely_mcp_config(".mcp.yaml")
    assert is_likely_mcp_config("mcp.yml")
    assert is_likely_mcp_config("claude_desktop_config.yaml")
    assert is_likely_mcp_config(".cursor/mcp.json")
    assert is_likely_mcp_config(".cursor/mcp.yaml")
    assert is_likely_mcp_config(".vscode/mcp.yml")
    assert is_likely_mcp_config("nested/dir/.cursor/mcp.json")


def test_is_likely_mcp_config_rejects_unrelated_files():
    assert not is_likely_mcp_config("package.json")
    assert not is_likely_mcp_config("README.md")
    assert not is_likely_mcp_config("random-mcp-notes.json")


def test_discover_mcp_files_finds_known_filename(tmp_path):
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "unrelated.json").write_text("{}", encoding="utf-8")

    found = discover_mcp_files(str(tmp_path))
    relative = {f.relative_path for f in found}
    assert "mcp.json" in relative
    assert "unrelated.json" not in relative


def test_discover_mcp_files_supports_explicit_paths(tmp_path):
    custom = tmp_path / "custom-config.json"
    custom.write_text("{}", encoding="utf-8")

    found = discover_mcp_files(str(tmp_path), explicit_paths=["custom-config.json"])
    relative = {f.relative_path for f in found}
    assert "custom-config.json" in relative


def test_explicit_config_path_cannot_escape_scan_root(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"mcpServers": {}}', encoding="utf-8")

    with pytest.raises(ValueError, match="outside the scan root"):
        discover_mcp_files(str(root), explicit_paths=["../outside.json"])

    with pytest.raises(ValueError, match="outside the scan root"):
        discover_mcp_files(str(root), explicit_paths=[str(outside)])


def test_explicit_config_path_cannot_escape_through_parent_symlink(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    link = root / "linked"
    try:
        os.symlink(outside_dir, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    with pytest.raises(ValueError, match="outside the scan root"):
        discover_mcp_files(str(root), explicit_paths=["linked/mcp.json"])


def test_discover_mcp_files_ignores_git_and_node_modules(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")

    found = discover_mcp_files(str(tmp_path))
    relative = {f.relative_path for f in found}
    assert relative == {"mcp.json"}


def test_iter_candidate_files_skips_oversized_files(tmp_path):
    big_file = tmp_path / "huge.json"
    big_file.write_bytes(b"0" * 2048)

    found = iter_candidate_files(str(tmp_path), max_file_size=1024)
    assert all(f.relative_path != "huge.json" for f in found)



def test_discover_fails_closed_for_oversized_known_mcp_config(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_bytes(b" " * (DEFAULT_MAX_FILE_SIZE_BYTES + 1))

    with pytest.raises(ValueError, match="MCP config exceeds the .*byte limit"):
        discover_mcp_files(str(tmp_path))


def test_discover_fails_closed_for_symlinked_known_mcp_config(tmp_path):
    target = tmp_path / "target.json"
    target.write_text('{"command":"docs-server"}', encoding="utf-8")
    link = tmp_path / "mcp.json"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    with pytest.raises(ValueError, match="MCP config path is a symlink"):
        discover_mcp_files(str(tmp_path))


def test_discover_fails_closed_for_symlinked_directory(tmp_path):
    target_dir = tmp_path / "hidden-configs"
    target_dir.mkdir()
    (target_dir / "mcp.json").write_text('{"command":"docs-server"}', encoding="utf-8")
    link = tmp_path / "linked-configs"
    try:
        os.symlink(target_dir, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are not supported on this platform")

    with pytest.raises(ValueError, match="directory symlink prevents complete MCP config discovery"):
        discover_mcp_files(str(tmp_path))


def test_directory_walk_errors_are_not_silently_ignored(tmp_path, monkeypatch):
    def failing_walk(*args, **kwargs):
        kwargs["onerror"](PermissionError("permission denied"))
        yield from ()

    monkeypatch.setattr(os, "walk", failing_walk)
    with pytest.raises(PermissionError, match="permission denied"):
        iter_candidate_files(str(tmp_path))



def test_discover_mcp_files_finds_yaml_mcp_config(tmp_path):
    (tmp_path / "mcp.yaml").write_text(
        "mcpServers:\n  srv:\n    command: docs-server\n",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.yaml").write_text("notMcp: true\n", encoding="utf-8")

    found = discover_mcp_files(str(tmp_path))
    relative = {f.relative_path for f in found}
    assert relative == {"mcp.yaml"}
