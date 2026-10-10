# Changelog

Notable changes to MCP Security Check for GitHub are recorded here.

## 0.1.0 — initial release candidate (not yet published)

### Included

- Offline discovery and static inspection of recognizable MCP configuration files.
- Capability extraction for shell execution, filesystem access, network access,
  secrets, credentials, dynamic code execution, and related risk signals.
- Rule engine, same-component attack-path analysis, transparent risk scoring,
  and configurable `ALLOW` / `WARN` / `BLOCK` decisions.
- BASE-versus-HEAD capability diff for newly introduced or changed permissions.
- CLI output in terminal, JSON, Markdown, and SARIF 2.1.0 formats.
- GitHub composite Action with one authoritative scan for all report formats.
- Automated Action scenarios for allow, warn, block, capability escalation,
  malformed input, non-execution of dangerous-looking commands, and invalid inputs.
- Python test matrix for versions 3.9, 3.11, and 3.13.

### Security and reliability fixes before publication

- Fail closed when a discovered MCP config cannot be read or parsed.
- Fail with an error for a missing scan root, explicitly requested file, or policy file.
- Reject empty or non-mapping policy YAML instead of silently selecting defaults.
- Reject explicitly requested symlinked or oversized files rather than silently
  omitting them from a requested scan.
- Isolate components during attack-path analysis to avoid cross-component chains.

### Known limitations

- Detection is static and heuristic; scanned MCP commands are never executed.
- Discovery only covers documented, recognizable config paths.
- Passing CI is not proof that a repository is safe and does not guarantee
  detection of every malicious behavior.
- The first release has no hosted service, team dashboard, or organization-wide
  policy management.
