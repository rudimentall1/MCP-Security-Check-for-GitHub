# Project Tasks

This is a working backlog. Statuses below reflect the repository state inspected on 2026-11-26; re-check GitHub before acting because PR and CI state can change.

## P0 — release and supply-chain correctness

- [ ] **Verify PyPI Trusted Publishing after repository transfer.** Confirm the publisher owner/repository/workflow/environment values for `rudimentall1/MCP-Security-Check-for-GitHub` and `publish.yml`. Do not assume the previous organization-owned publisher remains valid.
- [ ] **Pin every third-party action in `.github/workflows/publish.yml` to a reviewed full commit SHA.** At review time the workflow used `actions/upload-artifact@v4`, `actions/download-artifact@v4`, and `pypa/gh-action-pypi-publish@release/v1`, while the changelog claimed full-SHA pinning.
- [ ] **Reconcile Dependabot PRs #1–#3.** They were open and their PR Python Tests runs passed at review time:
  - #1 `actions/setup-python` 7.0.0 → 7.1.0 (updates full-SHA references).
  - #2 `actions/download-artifact` 4 → 8 (ESM/runtime major update).
  - #3 `actions/upload-artifact` 4 → 7 (ESM/runtime major update).
  Review the publish workflow end to end, including artifact upload/download compatibility and runner requirements, before merging.

## P1 — documentation consistency

- [ ] Review README claims against actual release and package registry state; PyPI availability was not independently checked in the 2026-11-26 review.
- [ ] Keep the changelog's release status and documented action-pinning claims aligned with actual GitHub releases and workflow files.
- [ ] Review `docs/PRO-PLATFORM-ARCHITECTURE.md` for any remaining references to the old OwneraLabs repository owner and update operational instructions after verifying the actual external configuration.
- [ ] Confirm whether the example Action SHA in README should remain the tested reference or be updated after a new Action release.

## P2 — product validation and future Pro work

- [ ] Validate demand for hosted history, shared workspaces, centralized policies and audit exports with real users before implementing a large hosted service.
- [ ] Seek 3–5 paid design partners before committing to the proposed Pro scope.
- [ ] Before any live billing: implement and test authentication, authorization, Stripe signature verification, idempotent webhook processing, entitlement reconciliation, cancellation, privacy/retention/export/deletion controls and operational monitoring.
- [ ] Do not advertise Pro as available until the paid service is implemented, deployed, tested end to end and purchasable.

## Completed in this documentation change

- [x] Add repository working rules in `AGENTS.md`.
- [x] Add a source-backed architecture, dependency, CI and status summary in `PROJECT_CONTEXT.md`.
- [x] Record known follow-up work without presenting it as completed.
