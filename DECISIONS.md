# Architecture and Product Decisions

This file records decisions supported by the current repository state and explicit project documentation. Proposed items are labelled as proposals, not implementation facts.

## D-001 — Python package with src layout

**Status:** Implemented.

The scanner is distributed as `mcp-security-check`, uses Python `>=3.11`, setuptools, and a `src/mcp_security` package layout. Runtime dependencies currently include PyYAML; pytest is a development dependency.

**Evidence:** `pyproject.toml`, source tree and CI workflow.

## D-002 — Free core remains offline and usable without Pro

**Status:** Product guardrail documented.

The CLI, GitHub Action, core rules, BASE/HEAD diff and standard reports remain free and must not require a Pro account, network call, license check or hosted entitlement. Paid value, if implemented, should focus on hosted history, team coordination, centralized policy and audit workflows rather than withholding core security findings.

**Evidence:** README and `docs/COMMERCIAL-STRATEGY.md`.

## D-003 — Pro is a future hosted service, not a current product capability

**Status:** Planned; not implemented in the reviewed repository.

The architecture document proposes FastAPI, PostgreSQL, GitHub OAuth and Stripe. No hosted service implementation was present in the reviewed master tree. Pricing in the commercial strategy is experimental and unvalidated.

**Guardrail:** Do not describe Pro as live, deployed, purchasable or production-ready until implementation and end-to-end operational evidence exist.

## D-004 — Static analysis; no execution of scanned configuration

**Status:** Implemented/documented security boundary.

The scanner statically inspects recognizable configuration files. It must not execute MCP commands, downloaded code, shell strings or arbitrary content from scanned repositories. Findings describe potential impact and heuristic signals, not proof of malware.

**Evidence:** README security model, discovery/parser implementation and regression tests.

## D-005 — GitHub default branch and contribution workflow

**Status:** Current repository convention.

The default branch is `master`. Work should be developed on focused branches and proposed through pull requests targeting `master`; do not assume a `main` branch or push directly to the default branch.

## D-006 — Documentation changes travel with implementation changes

**Status:** Mandatory repository working agreement.

Significant changes must update relevant documentation, documentation must be reviewed before task completion, and documentation must be committed in the same commit as the corresponding code/configuration change. See `AGENTS.md`.

## D-007 — Release 0.1.0

**Status:** GitHub Release published.

GitHub Release `v0.1.0` was published on 2026-11-23. The `Publish to PyPI` workflow run `45156853519` completed successfully: both the source distribution and wheel were uploaded, the PyPI endpoint returned HTTP 200 for each, and publish attestations were generated. Direct PyPI project metadata was not independently fetched. The current Trusted Publisher configuration after the repository transfer remains unverified.

## D-008 — Repository ownership

**Status:** Transfer verified.

The repository is now `rudimentall1/MCP-Security-Check-for-GitHub`, with `master` as its default branch. Any external integrations that depend on the old `OwneraLabs` owner (including PyPI Trusted Publishing) must be checked explicitly; do not assume their settings migrated automatically.


## D-009 — Pin third-party GitHub Actions by full commit SHA

**Status:** Mandatory repository policy; implementation included in PR #5.

All third-party GitHub Actions must use full commit SHAs, with a human-readable version comment. Updates must be reviewed for release notes, runtime requirements, and workflow compatibility. The artifact transfer in the PyPI publish workflow uses upload-artifact v7.0.2 and download-artifact v8.0.2, both Node 24 actions; the workflow runs on GitHub-hosted `ubuntu-latest` runners. PyPI publishing is pinned to the reviewed `release/v1` commit rather than a mutable branch name.

**Evidence:** `AGENTS.md`, workflow files, and upstream Action release/commit metadata.

## D-010 — Advisory architectural lint

**Status:** Adopted for CI as an advisory review signal.

The repository uses `deslop-please` to surface structural concerns in Python source. Its findings do not establish malicious behavior, and the tool does not replace the product's own static security analysis or tests. The workflow is isolated from package/runtime dependencies, uploads inspectable reports, and does not block product CI on findings or scan-time errors.

**Guardrails:** pin the CLI to a reviewed commit and all GitHub Actions by full SHA; never execute scanned repository content; do not create a blanket allowlist; review diagnostics before code changes.

**Evidence:** `.github/workflows/architecture-audit.yml`, `docs/ARCHITECTURE-QUALITY.md`, and `AGENTS.md`.
