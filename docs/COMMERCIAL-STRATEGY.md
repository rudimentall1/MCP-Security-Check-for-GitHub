# Commercial Strategy: Free Core + Pro

**Status:** Product decision / implementation plan  
**Last updated:** 2026-11-23  
**Current release:** 0.1.0

## Executive decision

Build MCP Security Check as an open-core product:

- Keep the local scanner, core detection rules, CLI, GitHub Action, BASE-vs-HEAD capability diff, and standard machine-readable reports free and usable without an account or license key.
- Monetize team workflows and hosted capabilities that create ongoing operational value: centralized policy management, organization-wide visibility, historical results, audit exports, and managed integrations.
- Do not charge per scan in the initial model. AI agents and CI pipelines must be able to run the free scanner unattended.
- Do not market planned Pro capabilities as available until they are implemented, tested, and purchasable.

The product's initial wedge is **MCP security change control in GitHub pull requests**: identify newly introduced capabilities and risky combinations before merge.

## Positioning

MCP Security Check is an MCP Security Gate for GitHub and AI-agent development workflows.

It is not currently a runtime MCP firewall, 24/7 monitor, malware verdict engine, or automatic incident-response platform. Findings are static, heuristic risk signals that require human review.

## Plans

### Free — $0

Available to individuals, public repositories, and automation:

- Local/offline configuration scanning.
- CLI and GitHub Action.
- Core detection rules and attack-path analysis.
- BASE-vs-HEAD capability diff.
- JSON, SARIF, Markdown, and terminal reports.
- Custom policy file support available in the open-source core.
- No account, API key, scan quota, or per-run fee.

### Pro Individual — proposed $5/month

A future paid offering, not yet available:

- Personal hosted workspace.
- Historical scan results and change history.
- Saved policy profiles and reusable policy packs.
- Convenient report retention and export.
- Priority support / early access, subject to capacity.

### Pro Team — proposed $19/month starting price

A future paid offering, not yet available:

- Shared organization workspace.
- Centralized policy distribution across repositories.
- Team-level findings and risk trends.
- Audit history and downloadable evidence.
- Multiple repository management and team collaboration.
- Higher retention and support level than Individual.

Prices are experiments, not validated market prices. Reassess after interviews and the first 3–5 paying customers. Do not introduce usage-based pricing until actual infrastructure costs and usage patterns are known.

## Product boundary: what stays free vs paid

Security fundamentals must remain free. Do not weaken or artificially limit core detection to force an upgrade.

The paid value should come from **coordination, persistence, and scale**, not withholding a critical warning:

| Capability | Free | Pro |
|---|---:|---:|
| Local scan and CLI | Yes | Yes |
| GitHub Action / PR gate | Yes | Yes |
| Core rules and attack paths | Yes | Yes |
| BASE-vs-HEAD diff | Yes | Yes |
| JSON / SARIF / Markdown output | Yes | Yes |
| Local custom policy file | Yes | Yes |
| Hosted history and retention | — | Yes |
| Shared team workspace | — | Yes |
| Central policy distribution | — | Yes |
| Organization-wide repository overview | — | Yes |
| Audit exports and team reporting | Basic local output | Extended hosted reports |

## Automatic sales and delivery

GitHub repository pages do not provide a native checkout-to-license system for arbitrary paid features. The intended purchase flow is:

1. A user clicks **Upgrade to Pro** in the README, GitHub Marketplace listing (if/when eligible), or product website.
2. The link opens an external hosted checkout.
3. The payment provider confirms payment through a signed webhook.
4. A licensing service creates or updates the subscription entitlement.
5. The customer receives an account invitation or license activation link automatically.
6. The GitHub App is installed/authorized and connected to selected repositories.
7. The hosted Pro service applies team entitlements and provides the paid workflows.

The open-source CLI and GitHub Action continue to work without contacting the licensing service. Do not embed payment secrets or private signing keys in the repository or client package.

A client-side license check alone is not strong enforcement when the client is open source and user-controlled. Therefore, paid value should primarily live in hosted services (team workspace, hosted history, centralized policy distribution), where entitlements can be enforced server-side.

## Implementation phases

### Phase 0 — documented decision (now)

- Publish this commercial strategy.
- Keep Free functionality intact.
- Clearly label Pro as planned, not currently purchasable.
- Avoid a fake checkout, placeholder license key, or non-functional Pro command-line flag.

### Phase 1 — validate demand

- Add a clear Free / Pro explanation and a waitlist/contact path.
- Recruit 20–50 relevant users.
- Conduct short interviews around multi-repository policy management, audit evidence, and history.
- Seek 3–5 paid design partners before building a large hosted platform.

### Phase 2 — minimum sellable Pro

Build only after demand validation:

- Hosted account and organization model.
- GitHub App for repository installation and webhook ingestion.
- Hosted scan history and team dashboard.
- Central policy profiles.
- Subscription checkout and signed payment webhooks.
- Server-side entitlement checks, cancellation, renewal, and grace-period handling.
- Privacy policy, terms, retention controls, deletion/export, and security review.

### Phase 3 — expand based on usage

Potential additions: policy packs, audit/compliance exports, integrations, repository risk trends, and advanced provenance analysis. Prioritize based on paid customer feedback.

## Success criteria

Initial validation targets:

- 20–50 real users or teams trying the Free scanner.
- At least 5 detailed feedback conversations.
- 3–5 paying design partners or clear evidence of willingness to pay.
- Evidence that users repeatedly need centralized policies, history, or audit reporting.

If users only want one-off local scans and do not value hosted team workflows, revisit the paid feature set before building it.

## Decisions and guardrails

- Free core remains useful and automation-friendly.
- No scan-by-scan paywall in the initial product.
- No claim that Pro is available until checkout, provisioning, entitlements, and paid features work end to end.
- No claim of runtime protection or continuous monitoring until those capabilities exist.
- Never make an ALLOW result sound like a guarantee of safety.
- Keep pricing and feature boundaries transparent.
