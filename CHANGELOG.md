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
- Package-build validation for source/wheel distributions, plus clean-environment CLI checks for both safe ALLOW and dangerous BLOCK cases.
- Automated Action scenarios for allow, warn, block, capability escalation,
  malformed input, non-execution of dangerous-looking commands, and invalid inputs.
- Python support is limited to maintained interpreter versions, with CI on 3.11–3.14.
- GitHub Actions are pinned to full commit SHAs and checked for updates by Dependabot.
- Node 24-compatible GitHub Actions dependencies to avoid deprecated runtime warnings.

### Security and reliability fixes before publication

- Pass composite Action inputs through environment variables rather than interpolating
  them into shell source, preventing shell-looking paths from becoming commands.
- Fail closed when a discovered MCP config cannot be read, parsed, or normalized
  to a recognizable server structure.
- Validate MCP server transport fields and the types of declared tools, args,
  environment, and permissions so malformed data cannot disappear into defaults.
- Fail with an error for a missing scan root, explicitly requested file, or policy file.
- Reject empty or non-mapping policy YAML instead of silently selecting defaults.
- Reject automatic or explicitly requested MCP config paths that are symlinked
  or oversized rather than silently omitting them.
- Surface directory traversal errors instead of accepting an incomplete scan.
- Detect and redact likely hardcoded credentials in remote MCP HTTP headers.
- Detect short literal values in credential-named environment variables and HTTP headers while ignoring placeholders and runtime references.
- Detect literal credential values embedded in URL query, fragment, and userinfo fields, while keeping report evidence redacted.
- Match credential-bearing URL parameter names by exact names and meaningful suffixes, avoiding substring false positives such as `tokenizer`.
- Sanitize report-level component names, file labels, scan errors, attack-path text, and capability-diff targets at the shared report boundary, including terminal/Markdown/JSON/SARIF output.
- Redact URL userinfo, sensitive query/fragment values, and Bearer/Basic tokens
  from finding text and capability-diff targets before output.
- Preserve HTTP header references such as ${input:accessToken} without reporting
  them as committed literal secrets.
- Add regression coverage for portable mcpServers and VS Code servers configs.
- Isolate components during attack-path analysis to avoid cross-component chains.

### Known limitations

- Detection is static and heuristic; scanned MCP commands are never executed.
- Discovery only covers documented, recognizable config paths.
- Passing CI is not proof that a repository is safe and does not guarantee
  detection of every malicious behavior.
- The first release has no hosted service, team dashboard, or organization-wide
  policy management.
