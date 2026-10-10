# Security Policy

## Reporting a vulnerability

Please do not publish exploitable vulnerability details in a public issue.

If GitHub's private vulnerability reporting is enabled for this repository,
use the repository's **Security** tab to submit a private report. If that
option is not available, contact the repository maintainer privately through
the maintainer's GitHub profile before disclosing details publicly.

Include the affected commit, the exact command/configuration needed to reproduce
the issue, expected versus actual behavior, and any impact on scanned data or
the GitHub Action's security decision. Do not include real credentials or
production secrets in the report.

## Scope and limitations

MCP Security Check statically analyzes recognizable configuration files. It
does not execute scanned commands and is not a malware verdict. Heuristics can
miss behavior or produce false positives; passing a scan does not guarantee
that an MCP server or repository is safe.

Until a versioned release is published, the current default branch is the only
maintained development line. Please report security issues even if they affect
the development branch rather than a released version.
