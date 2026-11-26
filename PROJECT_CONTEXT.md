# Project Context

**Repository:** `rudimentall1/MCP-Security-Check-for-GitHub`  
**Default branch:** `master`  
**Last context review:** 2026-11-26  
**Reviewed master commit:** `cab78740cf77ea2fd43685e447abce306308317b`

## Product summary

MCP Security Check is a static security-analysis tool for Model Context Protocol (MCP) server and AI-agent configuration. It extracts capabilities from recognizable configuration files, evaluates rules and same-component attack paths, and can compare BASE and HEAD capability sets.

The verified product surfaces in this repository are:
- Python CLI: `mcp-security-check scan` and `mcp-security-check diff`.
- GitHub composite Action defined in `action.yml`.
- Terminal, JSON, Markdown, and SARIF reports.
- Local policy configuration through YAML.

The scanner does not execute MCP commands or configuration content. Its analysis is static and heuristic; results require human review and do not guarantee detection of every malicious behavior.

## Technology and dependencies

Source of truth: `pyproject.toml`.

- Distribution/package: `mcp-security-check`, version `0.1.0`.
- Python: `>=3.11`.
- Build backend: setuptools.
- Runtime dependency: `PyYAML>=6.0`.
- Development extra: `pytest>=7.0`.
- Source layout: `src/mcp_security`.
- Test root: `tests`; pytest adds `src` to `pythonpath`.

There is no root `package.json` in the reviewed repository tree. Do not assume Node.js/npm tooling is part of this project.

## Repository structure

- `src/mcp_security/cli.py` — command-line interface.
- `src/mcp_security/engine.py` — scan orchestration.
- `src/mcp_security/discovery/` — configuration discovery and MCP normalization.
- `src/mcp_security/parsers/` — JSON/YAML and skill parsing.
- `src/mcp_security/analyzers/` — capability, permission, provenance, secret and attack-path analysis.
- `src/mcp_security/rules/` and `rules/default.yaml` — detection rules and defaults.
- `src/mcp_security/diff/` — BASE/HEAD capability comparison.
- `src/mcp_security/model/` — domain models.
- `src/mcp_security/scoring/` — risk and trust scoring.
- `src/mcp_security/output/` — terminal, Markdown and SARIF rendering.
- `src/mcp_security/redaction.py` — report sanitization.
- `src/mcp_security/github/` — GitHub-specific output helpers.
- `tests/` — unit, regression, CLI, parser, output, security-redaction and realistic-config tests.
- `examples/` — safe/dangerous MCP examples and Action workflow example.
- `.github/workflows/python-tests.yml` — Python test matrix, YAML validation, package build and wheel smoke tests.
- `.github/workflows/action-self-test.yml` — composite Action scenarios.
- `.github/workflows/publish.yml` — tagged release build and PyPI Trusted Publishing.
- `docs/PRO-PLATFORM-ARCHITECTURE.md` — proposed hosted Pro architecture.
- `docs/COMMERCIAL-STRATEGY.md` — Free/Pro positioning and validation plan.

The latest recursive Git tree inspection returned 116 entries with `truncated=false`.

## Architecture and product boundary

The Free scanner, CLI, rules, reports and GitHub Action are local/open-source capabilities. They must remain usable without Pro credentials or a hosted service.

The Pro platform documentation is an implementation blueprint. It proposes FastAPI, PostgreSQL, GitHub OAuth and Stripe, but this repository's reviewed tree does not contain an implemented hosted Pro service. Do not present Pro as live, purchasable, or deployed without new implementation and operational evidence.

Commercial strategy proposes Individual and Team price points as experiments, not validated market prices. It recommends demand validation before building a large hosted platform.

## CI and release workflow

The Python Tests workflow:
- runs on push, pull request and manual dispatch;
- tests Python 3.11, 3.12, 3.13 and 3.14;
- validates Action/workflow YAML;
- builds and checks source/wheel distributions;
- installs the wheel in a clean virtual environment and smoke-tests ALLOW and BLOCK behavior.

The publish workflow triggers on tags matching `v*`, checks the tag against `pyproject.toml`, builds distributions, transfers the artifact between jobs, and uses PyPI Trusted Publishing with an OIDC token.

Third-party Action references are pinned to full commit SHAs. The reviewed pins in this change are: `actions/checkout` v7 (`3d3c42e5...`), `actions/setup-python` v7.1.0 (`6d4fd22b...`), `actions/upload-artifact` v7.0.2 (`cf430e03...`), `actions/download-artifact` v8.0.2 (`9000827c...`), and `pypa/gh-action-pypi-publish` `release/v1` (`7245906f...`). The README and example workflow both pin the composite Action to `54a16d29...`; the example also pins CodeQL Action v4.38.3 and `actions/github-script` v9.0.0 by full SHA.

## Verified repository state on 2026-11-26

- Latest reviewed `master` commit: `cab78740cf77ea2fd43685e447abce306308317b` — full-SHA Action pinning, Node 24-compatible artifact actions, and synchronized Action examples.
- GitHub Release `v0.1.0` exists and was published on 2026-11-23.
- README states that version 0.1.0 is available on PyPI. PyPI registry availability was not independently queried in this review.
- Python Tests run for the reviewed master commit completed successfully. Inspected jobs: package build/smoke test and pytest on Python 3.11, 3.12, 3.13 and 3.14; all reported success.
- Action Self-Test run for the reviewed master commit completed successfully; all 11 scenario jobs passed.
- Dependabot PRs #1–#3 were closed after their changes were incorporated into PR #5. No open pull requests remained at the time of this review.
- No open issues were returned by the repository issue search at review time.
- No local checkout was available for this review; runtime tests were not executed locally. CI evidence is recorded above.

## Known documentation and maintenance risks

- The Pro architecture document's stale migration checklist was corrected in this documentation change to reflect the verified transfer from OwneraLabs to `rudimentall1`. External integration settings still require separate verification.
- Confirm PyPI Trusted Publisher configuration after repository ownership transfer before the next release. Do not assume the publisher configuration transferred automatically.

## Working commands

From the repository root, using Python 3.11 or newer:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m build
python -m twine check dist/*
```

The build commands require the optional `build` and `twine` tools to be installed. The repository CI installs them explicitly.

## Maintenance rule

Keep this document aligned with actual code, dependencies, CI, releases and decisions. Record review dates and commit SHAs. Mark unknown or unverified details explicitly rather than inferring them.
