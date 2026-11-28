# Architecture Quality Audit

**Status:** advisory pilot enabled for pushes to `master`, pull requests targeting `master`, and manual dispatch.  
**Workflow:** `.github/workflows/architecture-audit.yml`  
**Scope:** Python source projects.

## Toolchain

- `deslop-please` pinned to commit `cfabfb9ee417e150d5342e8ef0d6a0fe725cc9a0`;
- Rust `1.99.0` to build the CLI;
- `@sourcegraph/scip-python@0.6.8` to create the SCIP index.

These tools run only on ephemeral GitHub Actions runners. They are not added to application/runtime dependencies or lockfiles. The scanner reads source and writes indexes to its user cache; it does not rewrite project files.

## Diagnostics

The scanner reports module cycles, tangled dependency groups, object-field leaks, shallow module interfaces, wide directories, and long files. A diagnostic is a structural signal, not proof of a defect. Review the real dependency and ownership boundaries before changing code.

## Execution and reporting

The workflow uploads JSON diagnostics and indexer stderr as a 14-day Actions artifact.

- Exit `0`: no architectural findings.
- Exit `1`: findings were reported.
- Exit `2`: the scan could not complete because of a tool, indexer, or configuration error.

The scan step is advisory and does not block existing application CI. Installation/setup failures still fail this separate workflow. The step summary distinguishes findings from execution errors; an execution error must never be treated as a clean scan.

No allowlist is configured, and the workflow never runs `--update-allow`.

## Local execution

On Ubuntu 24.04 with Rust 1.99.0 and Node.js 22:

```bash
cargo install --git https://github.com/Bor4brn/deslop-please --rev cfabfb9ee417e150d5342e8ef0d6a0fe725cc9a0 --locked deslop-please
npm install --global --no-audit --no-fund @sourcegraph/scip-python@0.6.8
deslop-please --language python --json
```

Indexes are cached outside the repository. No source changes are made by the tool.

## Coverage limits

- Only Python code is scanned. The tool does not evaluate detection-rule quality, malicious-input coverage, secrets redaction, or Action behavior.

This is not a security audit. It does not check authorization correctness, cryptography, dependency CVEs, secrets, or runtime behavior. It does not replace the repository's existing tests, threat-model review, dependency review, or live evidence requirements.

## Initial scan baseline — 2026-11-28

The first completed scan is [Architecture Audit run #46113431076](https://github.com/rudimentall1/MCP-Security-Check-for-GitHub/actions/runs/46113431076) against source head `26883243c5a22f1df2d601a997c3072b5f4f0d94`. The analyzer returned exit code `1` with **5 diagnostics** (4 field-leak, 1 wide-directory). This is a review baseline, not a list of confirmed defects.

Findings concern `Capability.metadata`, `Finding.severity` (16 references across 8 modules), and `Policy.block_on` / `Policy.warn_on`; `tests/` is wide (17 entries). Review whether these are immutable value-model fields or mutable policy controls. The scan does not test the security rules, parser correctness, secret redaction, or composite Action behavior.

The JSON report and indexer stderr are available in [artifact 15250682620](https://github.com/rudimentall1/MCP-Security-Check-for-GitHub/actions/runs/46113431076/artifacts/15250682620), retained for 14 days. No application source was changed and no diagnostic was suppressed. Keep this as a dated snapshot rather than a claim about later commits.
