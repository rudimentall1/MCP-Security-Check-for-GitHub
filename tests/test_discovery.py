import os
import tempfile

from mcp_security.discovery.files import iter_candidate_files
from mcp_security.discovery.mcp import discover_mcp_files, is_likely_mcp_config


def test_is_likely_mcp_config_matches_known_filenames():
    assert is_likely_mcp_config(".mcp.json")
    assert is_likely_mcp_config("mcp.json")
    assert is_likely_mcp_config("claude_desktop_config.json")
    assert is_likely_mcp_config(".cursor/mcp.json")
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
