# MCP Security Check for GitHub

Scan MCP servers, AI-agent permissions and attack paths before merging a GitHub pull request.

## 1. What it is

MCP Security Check is an offline, GitHub-native security analysis engine for
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) configuration.
It inspects MCP server definitions found in a repository, extracts a normalized
set of **capabilities** (what a server can actually *do* — read files, execute
shell commands, reach the network, read secrets, ...), and evaluates them
against a rule engine, an attack-path engine, and a capability-diff engine.

It runs as a CLI, a GitHub Action, and produces JSON, SARIF, and PR-friendly
Markdown output.

## 2. Why it exists

MCP servers and AI-agent tool configurations can grant an agent powerful,
composable capabilities — shell execution, filesystem write, secret access,
unrestricted network egress. Individually these can be legitimate. Combined,
they frequently form a realistic attack path (e.g. "read secrets, then reach
an external network" = exfiltration). Most existing scanners only pattern-match
individual strings. This project's core differentiator is comparing **BASE vs
HEAD** capability sets on a pull request and flagging *newly introduced*
dangerous capabilities and combinations before merge — not just scanning a
snapshot.

## 3. What it detects

- Individual dangerous capabilities (shell execution, unrestricted filesystem
  write, unrestricted network, secret/credential access, dynamic code
  execution, remote script execution, ...)
- Dangerous **combinations** of capabilities on the same component
- **Newly introduced** capabilities in a pull request (capability diff)
- Multi-step **attack paths** (e.g. `filesystem.write → shell.execute →
  network.external`)
- Suspicious configuration signals (obfuscated content, external instruction
  fetching, unpinned dependencies, unverified/unknown-publisher remote
  sources, possible hardcoded secrets)

See [Rules](#8-rules) and [Attack paths](#9-attack-path-engine) below for the
full list.

## 4. Example security report

```
MCP SECURITY CHECK

Decision: BLOCK
Risk Score: 87/100

Critical: 1
High: 2
Medium: 3
Low: 1

Permission Changes:

+ filesystem.write
+ shell.execute
+ network.external

Attack Paths:

[CRITICAL] filesystem.write → shell.execute → network.external
  Critical multi-step attack path: ...

Findings:

MSC001 [HIGH] Arbitrary Shell Execution (mcp.json)
MSC005 [CRITICAL] Shell Execution + External Network (mcp.json)
```

A GitHub PR comment (Markdown) rendering of the same report is shown further
down in this document, in [examples/github-action.yml](examples/github-action.yml)
usage and [examples/dangerous-mcp.json](examples/dangerous-mcp.json).

## 5. GitHub Action installation

```yaml
name: MCP Security

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          path: head
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: base

      - name: MCP Security Check
        id: mcp_check
        uses: rudimentall1/MCP-Security-Check-for-GitHub@bd8489a0964f23071b779556ea38d75352c22b90
        with:
          path: head
          base-path: base
          fail-on: critical
```

This quick start pins a reviewed commit SHA rather than an unpublished version tag.
Update that SHA deliberately after reviewing a newer commit.

See [action.yml](action.yml) for all inputs/outputs and
[examples/github-action.yml](examples/github-action.yml) for a complete
workflow including SARIF upload, a PR comment, and the `push`/manual-trigger
fallback (the minimal example above assumes a `pull_request` trigger with
both BASE and HEAD checked out). The full example skips SARIF upload and PR
comments for fork-originated PRs, whose token is read-only.

Inputs: `path`, `base-path` (optional — when set, runs a capability diff
instead of a single-tree scan; see the comment in
[action.yml](action.yml) on how BASE/HEAD are obtained and the documented
fallback behavior for non-PR triggers), `config`, `format`, `fail-on`.

Outputs: `decision`, `risk-score`, `report-path`, `sarif-path`. All four are
produced by a **single** internal `mcp-security-check` invocation (scan or
diff) so they can never disagree with each other — the Action never re-runs
the analysis to compute outputs separately from the report it writes.

## 6. CLI usage

Install the current code directly from GitHub (until a PyPI release is published):

```bash
python -m pip install "git+https://github.com/rudimentall1/MCP-Security-Check-for-GitHub.git@bd8489a0964f23071b779556ea38d75352c22b90"

mcp-security-check scan .
mcp-security-check scan . --format json
mcp-security-check scan . --format sarif --output results.sarif
mcp-security-check diff <base-dir> <head-dir>
mcp-security-check scan . --config .mcp-security.yaml --fail-on high
```

Options: `--config`, `--format {terminal,json,sarif,markdown}`, `--output`,
`--sarif-output` / `--markdown-output` (write those formats to additional
files from the *same* analysis run, alongside `--output`/`--format` —
useful for producing JSON+SARIF+Markdown from one invocation, as the
GitHub Action does), `--fail-on {critical,high,medium,low,info}`,
`--file` (repeatable, explicit config path), `--verbose`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ALLOW |
| 1 | WARN |
| 2 | BLOCK |
| 3 | incomplete scan, input, or execution/configuration error |

## 7. Configuration

Policy is a small YAML file (see [rules/default.yaml](rules/default.yaml)):

```yaml
policy:
  block_on: [critical]
  warn_on: [high, medium]
  block_on_critical_attack_path: true
  rules:
    MSC009:
      action: warn
    MSC001:
      action: block
  allowed_capabilities: []
  allowed_endpoints: []
```

`rules.<RULE_ID>.action` can be `block`, `warn`, `allow`, or `ignore`.
`allowed_capabilities` / `allowed_endpoints` suppress findings for
capabilities/endpoints you have explicitly reviewed and approved.

## 8. Rules

| ID | Title |
|---|---|
| MSC001 | Arbitrary Shell Execution |
| MSC002 | Secret Access |
| MSC003 | Secret + External Network |
| MSC004 | Filesystem + External Network |
| MSC005 | Shell + External Network |
| MSC006 | Unrestricted Filesystem Write |
| MSC007 | Credential File Access |
| MSC008 | Remote Script Execution |
| MSC009 | Unrestricted Network |
| MSC010 | Package Install + Execute |
| MSC011 | Dynamic Code Execution |
| MSC012 | Dangerous MCP Tool |
| MSC013 | External Instruction Fetch |
| MSC014 | Obfuscated Instruction |
| MSC015 | New High-Risk Capability (capability diff) |
| MSC016 | Unpinned Dependency |
| MSC017 | Unverified Remote Source |
| MSC018 | New External Endpoint (capability diff) |
| MSC019 | Unknown Publisher |
| MSC020 | Configuration Drift (capability diff) |

**Severity rationale:** CRITICAL is reserved for combinations with a
realistic exploit chain (e.g. shell + network, secrets + network) and for
remote-script-execution patterns (`curl ... \| sh`). Single dangerous
capabilities (shell execution alone, filesystem write alone, unrestricted
network alone) are HIGH — dangerous, but common in legitimate tooling.
Access-adjacent signals (secret env var naming, credential declarations) are
MEDIUM. Provenance/metadata gaps (unknown publisher, unpinned version) are
LOW/MEDIUM informational hints, not proof of danger. A dangerous capability
is never treated as proof of malware — findings state the possible impact,
not a verdict.

Unknown/unrecognized configuration fields and permission strings are never
translated into a capability or a finding — unknown data does not mean
dangerous data.

## 9. Attack path engine

The attack-path engine evaluates **combinations** of capabilities present on
the same component (independent of single-capability rules):

| ID | Chain | Severity |
|---|---|---|
| AP001 | secrets.read → network.external | CRITICAL |
| AP002 | filesystem.read → network.external | HIGH |
| AP003 | filesystem.write → shell.execute | CRITICAL |
| AP004 | shell.execute → network.external | CRITICAL |
| AP005 | package.install → package.execute | HIGH |
| AP006 | credentials.read → network.external | CRITICAL |
| AP007 | filesystem.write → shell.execute → network.external | CRITICAL |

## 10. Capability diff

`mcp-security-check diff <base> <head>` (or the Action's `base-path` input)
parses both trees and computes:

- `added` — capabilities present in HEAD but not BASE
- `removed` — capabilities present in BASE but not HEAD
- `unchanged` — capabilities present in both with the same target/scope
- `changed` — capabilities present in both, but whose target/scope changed
  (reported as MSC020 Configuration Drift)

Newly added high-risk capabilities trigger MSC015; a newly added
`network.external` capability additionally triggers MSC018 (New External
Endpoint). The diff engine is independent of GitHub — it operates purely on
two capability sets and is used by both the CLI and the Action.

## 11. Risk scoring

The score is a **documented, reproducible weighted sum**, capped at 100 — not
an opaque AI/ML score:

```
score = sum(severity_weight[f] for f in findings)
      + sum(attack_path_bonus[p] for p in attack_paths)
      + (15 if a new high-risk capability was added else 0)
score = min(score, 100)
```

| Severity | Finding weight | Attack-path bonus |
|---|---|---|
| critical | 40 | 25 |
| high | 20 | 12 |
| medium | 10 | 5 |
| low | 3 | 0 |
| info | 0 | 0 |

See [scoring/risk.py](src/mcp_security/scoring/risk.py) for the exact
implementation.

## 12. ALLOW / WARN / BLOCK

Default decision logic (configurable via policy, see [§7](#7-configuration)):

- Any **CRITICAL** finding, or any **CRITICAL attack path** → **BLOCK**
- Any **HIGH** or **MEDIUM** finding (and nothing above) → **WARN**
- Otherwise → **ALLOW**

`--fail-on <severity>` on the CLI/Action additionally forces BLOCK if any
finding at or above that severity is present, independent of the policy
file's own thresholds.

If a discovered MCP configuration cannot be read, parsed, or normalized to a
recognizable MCP server structure, the report fails closed with **BLOCK** and
the CLI returns exit code **3**. A missing scan root,
missing explicit `--file`, missing policy file, or invalid/empty policy YAML
also returns exit code **3** instead of silently falling back to a clean scan
or the default policy. These errors do not claim the configuration is
malicious; they mean the requested assessment could not be completed.

## 13. Limitations

- MCP configuration is not universally standardized; discovery covers common,
  recognizable filenames/paths (`.mcp.json`, `mcp.json`,
  `claude_desktop_config.json`, `.cursor/mcp.json`, ...) — not every possible
  client's config layout.
- Capability extraction is heuristic (command names, argument tokens,
  environment variable naming, declared tool names/permissions). It can miss
  capabilities that are not expressible in the inspected fields, and it does
  not execute anything to verify behavior.
- Provenance/trust signals are informational only and based solely on local
  metadata; they are **not** proof that a component is trustworthy.
- Entropy-based hardcoded-secret detection and description-based heuristics
  (MSC013, MSC014, MSC002-LITERAL) can produce false positives; they are
  marked with lower confidence rather than certainty.
- This tool does not detect all attacks and does not guarantee protection —
  it surfaces dangerous capabilities and plausible attack paths for human
  review before merge.

## 14. Security model

The scanner only reads and analyzes text-based configuration files. It never:

- executes MCP commands, configuration commands, or skill instructions
- executes downloaded code or follows arbitrary URLs
- runs shell commands found in scanned content
- imports arbitrary modules from scanned repositories
- evaluates untrusted Python
- uses unsafe deserialization (`yaml.safe_load` only, standard `json.loads`
  only)
- follows symlinks during discovery or reads their targets. A symlinked MCP
  config, a non-ignored symlinked directory, or a recognizable MCP config over
  the size limit causes an explicit scan error rather than a misleading ALLOW.

File discovery enforces a size limit (default 2 MiB), skips oversized files
that are not recognized as MCP configs, and excludes VCS/dependency directories
(`.git`, `node_modules`, `.venv`, ...) to avoid scanning huge or irrelevant
trees. Directory traversal errors are surfaced instead of silently returning
a partial result.

## 15. Roadmap

**v0.2:** SKILL.md analysis, plugin support, baseline/rug-pull detection,
stronger provenance signals.

**v0.3:** policy-as-code, organization-wide policies, custom rules.

**v0.4:** machine-readable security API, MCP security tool interface.

**v0.5:** historical reports, team dashboard.

**Future:** AI Agent Security Gate, Agent Supply Chain Security, Web3 agent
security (the capability model already reserves `wallet.*`, `transaction.*`,
`contract.*`, `token.*` for this, but they are not a primary v0.1 feature).

## Development

```bash
pip install -e ".[dev]"
pytest
```

`pytest` works right after cloning, even without the `pip install -e .`
step above (see `[tool.pytest.ini_options]` in `pyproject.toml`) — the
install is still recommended so the `mcp-security-check` console script
and normal `import mcp_security` work outside of tests.

## Project status and security

- [CHANGELOG](CHANGELOG.md) — current release scope and known limitations.
- [Security policy](SECURITY.md) — responsible vulnerability reporting.

The first version has not been published as a GitHub Release or PyPI package yet.
The source can be installed using the commit-pinned command above.

## License

MIT — see [LICENSE](LICENSE).
