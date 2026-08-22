"""Command-line interface for mcp-security-check.

Exit codes:
    0 = ALLOW
    1 = WARN
    2 = BLOCK
    3 = execution/configuration error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from mcp_security.engine import scan, scan_diff
from mcp_security.model.report import Report
from mcp_security.output.markdown import render_markdown
from mcp_security.output.sarif import render_sarif
from mcp_security.output.terminal import render_terminal

EXIT_ERROR = 3


def _write_output(text: str, output_path: Optional[str]) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)
    if fmt == "sarif":
        return json.dumps(render_sarif(report), indent=2)
    if fmt == "markdown":
        return render_markdown(report)
    return render_terminal(report)


def _fail_on_to_severity_list(fail_on: str) -> List[str]:
    order = ["critical", "high", "medium", "low", "info"]
    if fail_on not in order:
        return ["critical"]
    idx = order.index(fail_on)
    return order[: idx + 1]


def _apply_fail_on(report: Report, fail_on: Optional[str]) -> Report:
    """Optionally tighten the decision based on a --fail-on threshold.

    This does not change findings/score, only whether WARN gets promoted
    to BLOCK for CLI/Action exit-code purposes, independent of the policy
    file's own block_on/warn_on configuration.
    """
    if not fail_on:
        return report
    from mcp_security.model.report import Decision

    severities = set(_fail_on_to_severity_list(fail_on))
    if report.decision == Decision.BLOCK:
        return report
    if any(f.severity.value in severities for f in report.findings):
        report.decision = Decision.BLOCK
    return report


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        report = scan(args.path, config_path=args.config, explicit_paths=args.file or None)
    except Exception as exc:  # noqa: BLE001 - CLI boundary, report cleanly
        sys.stderr.write(f"error: scan failed: {exc}\n")
        return EXIT_ERROR

    report = _apply_fail_on(report, args.fail_on)
    text = _render(report, args.format)
    _write_output(text, args.output)

    if args.verbose:
        sys.stderr.write(f"scanned {len(report.scanned_files)} file(s), {len(report.components)} component(s)\n")

    return report.decision.exit_code


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        report = scan_diff(args.base, args.head, config_path=args.config)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"error: diff failed: {exc}\n")
        return EXIT_ERROR

    report = _apply_fail_on(report, args.fail_on)
    text = _render(report, args.format)
    _write_output(text, args.output)
    return report.decision.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-security-check", description="Scan MCP configurations for dangerous capabilities and attack paths.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory for MCP configuration.")
    scan_parser.add_argument("path", help="Directory to scan.")
    scan_parser.add_argument("--config", default=None, help="Path to a policy YAML file.")
    scan_parser.add_argument("--format", choices=["terminal", "json", "sarif", "markdown"], default="terminal")
    scan_parser.add_argument("--output", default=None, help="Write output to this file instead of stdout.")
    scan_parser.add_argument("--fail-on", default=None, choices=["critical", "high", "medium", "low", "info"], help="Force BLOCK if any finding at or above this severity is present.")
    scan_parser.add_argument("--file", action="append", default=[], help="Explicit config file path to include (repeatable).")
    scan_parser.add_argument("--verbose", action="store_true")
    scan_parser.set_defaults(func=cmd_scan)

    diff_parser = subparsers.add_parser("diff", help="Compare MCP configuration between two directories (base vs head).")
    diff_parser.add_argument("base", help="Base directory (e.g. checkout of the target branch).")
    diff_parser.add_argument("head", help="Head directory (e.g. checkout of the PR branch).")
    diff_parser.add_argument("--config", default=None, help="Path to a policy YAML file.")
    diff_parser.add_argument("--format", choices=["terminal", "json", "sarif", "markdown"], default="terminal")
    diff_parser.add_argument("--output", default=None, help="Write output to this file instead of stdout.")
    diff_parser.add_argument("--fail-on", default=None, choices=["critical", "high", "medium", "low", "info"])
    diff_parser.set_defaults(func=cmd_diff)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
