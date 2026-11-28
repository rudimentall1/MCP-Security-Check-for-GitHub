# Project Tasks

This is a working backlog. Statuses below reflect the repository state inspected on 2026-11-26; re-check GitHub before acting because PR and CI state can change.

## P0 — release and supply-chain correctness

- [ ] **Verify PyPI Trusted Publishing after repository transfer.** Confirm the publisher owner/repository/workflow/environment values for `rudimentall1/MCP-Security-Check-for-GitHub` and `publish.yml`. Do not assume the previous organization-owned publisher remains valid.
- [x] Pin third-party Actions to full commit SHAs across `action.yml`, workflows, and the example: `actions/setup-python` v7.1.0, `actions/upload-artifact` v7.0.2, `actions/download-artifact` v8.0.2, and `pypa/gh-action-pypi-publish` at the reviewed `release/v1` commit. Exact pins are recorded in the source files.
- [x] Close superseded Dependabot PRs #1–#3 after their changes were incorporated into PR #5. All three PRs are now closed.

## P1 — documentation consistency

- [x] Verify the README's PyPI 0.1.0 release claim against the successful `Publish to PyPI` workflow run `45156853519`: both distributions uploaded with HTTP 200 and publish attestations. Direct PyPI project metadata was not independently fetched.
- [x] Keep the changelog's release status and documented action-pinning claims aligned with actual GitHub releases and workflow files.
- [x] Correct the stale repository-transfer checklist in `docs/PRO-PLATFORM-ARCHITECTURE.md`; external integration settings remain separately unverified.
- [x] Align the README and example workflow on the same reviewed composite Action commit SHA (`54a16d2968ef7ac30be6260e70157ada75819759`).

## P2 — product validation and future Pro work

- [ ] Validate demand for hosted history, shared workspaces, centralized policies and audit exports with real users before implementing a large hosted service.
- [ ] Seek 3–5 paid design partners before committing to the proposed Pro scope.
- [ ] Before any live billing: implement and test authentication, authorization, Stripe signature verification, idempotent webhook processing, entitlement reconciliation, cancellation, privacy/retention/export/deletion controls and operational monitoring.
- [ ] Do not advertise Pro as available until the paid service is implemented, deployed, tested end to end and purchasable.

## Completed in this documentation change

- [x] Add repository working rules in `AGENTS.md`.
- [x] Add a source-backed architecture, dependency, CI and status summary in `PROJECT_CONTEXT.md`.
- [x] Record known follow-up work without presenting it as completed.

## P2 — architecture maintainability

### Architecture quality scan

- [ ] Review the first `deslop-please` Python report; separate genuine design issues from heuristic findings.
- [ ] Keep the scanner advisory until findings are triaged and its value is demonstrated over multiple PRs.
