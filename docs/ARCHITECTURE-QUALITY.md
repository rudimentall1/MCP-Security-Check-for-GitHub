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
