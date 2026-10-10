"""End-to-end tests against realistic, source-documented MCP configs."""

import json
from pathlib import Path

from mcp_security.cli import main


def test_vscode_mixed_remote_and_stdio_config_scans_without_false_secret_finding(
    tmp_path, capsys
):
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "realistic"
        / "vscode-mixed-servers.mcp.json"
    )
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "mcp.json").write_text(
        fixture.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    exit_code = main(["scan", str(tmp_path), "--format", "json"])
    report_text = capsys.readouterr().out
    report = json.loads(report_text)

    assert exit_code in (0, 1), report
    assert report["errors"] == []
    assert report["scanned_files"] == [".vscode/mcp.json"]
    assert set(report["components"]) == {"github", "docs", "playwright"}
    assert not any(
        finding["rule_id"] == "MSC002-LITERAL"
        and finding["evidence"].startswith("headers.")
        for finding in report["findings"]
    )
