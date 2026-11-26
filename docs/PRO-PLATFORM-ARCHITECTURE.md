# OwneraLabs Pro Platform — Architecture

**Status:** implementation blueprint; no paid service is live yet.

## Product boundary

The Pro platform is a separate hosted service. The open-source MCP Security Check CLI and GitHub Action remain fully usable without a Pro account, API key, network call, or license check. Pro monetizes hosted history, shared workspaces, centralized policies, organization-level visibility, and audit exports.

## Initial stack

- Python 3.12+
- FastAPI REST API
- PostgreSQL
- GitHub OAuth for sign-in
- Stripe Checkout + Billing Portal for subscriptions
- Stripe signed webhooks as the source of truth for subscription state
- Render for initial hosting, subject to plan and cost review

## Core data model

- `users`: internal ID, GitHub numeric user ID, login, verified email, timestamps.
- `workspaces`: owner, name, plan, created/updated timestamps.
- `workspace_members`: workspace, user, role.
- `subscriptions`: workspace, Stripe customer ID, subscription ID, price ID, status, period end, cancel-at-period-end.
- `webhook_events`: unique Stripe event ID, event type, received timestamp, processing status.
- `entitlements`: workspace, feature key, enabled/limit, effective period.

Use database uniqueness constraints for GitHub IDs, Stripe IDs, membership pairs, and webhook event IDs. Never use a browser redirect as proof of payment.

## First API contract

- `GET /health` — liveness check.
- `GET /auth/github` and `GET /auth/github/callback` — OAuth login with state validation.
- `POST /auth/logout` — clear session.
- `GET /api/me` — current user and workspace entitlements.
- `POST /api/billing/checkout` — create Stripe subscription Checkout Session for the selected workspace.
- `POST /api/billing/portal` — create Stripe customer portal session.
- `POST /webhooks/stripe` — verify Stripe signature, persist event idempotently, update subscription and entitlements.
- `GET /api/workspaces` — list current user's workspaces.
- `GET /api/workspaces/{workspace_id}/subscription` — workspace plan and entitlement status.

All API errors should use a consistent machine-readable shape. Validate external inputs at API boundaries. Protect browser sessions with HttpOnly, Secure (production), SameSite cookies, CSRF/state checks, and a strong rotating session secret.

## Billing invariants

1. Checkout creation requires an authenticated user and workspace owner/admin permission.
2. Stripe secret keys and webhook secrets are server-side environment variables only.
3. Verify the raw webhook body with Stripe's signature verifier before parsing or mutating state.
4. Store every provider event ID under a unique constraint; duplicate delivery must be a no-op.
5. Grant Pro only for provider-confirmed `active` or `trialing` subscription states.
6. `past_due`, `unpaid`, `canceled`, `incomplete`, and deleted subscriptions must not silently retain active Pro.
7. Handle subscription created/updated/deleted and invoice payment-failed/payment-succeeded events.
8. A success URL is UX only. It never grants entitlements.
9. Keep a reconciliation job to compare local subscriptions with Stripe after launch.
10. Do not collect or store card numbers; Stripe-hosted Checkout handles payment details.

## First paid feature slice

Build only:
- GitHub sign-in.
- One personal workspace per user.
- Checkout and customer portal.
- Subscription status and entitlement display.
- Hosted scan-history API placeholder only after authentication and authorization are in place.

Do not build a complex organization/seat model until customer interviews validate it.

## Deployment and operations

- PostgreSQL with automated backups and tested restore.
- HTTPS only; configure trusted proxy headers correctly.
- Render secrets configured in the dashboard, never in Git.
- Health check endpoint and structured logs with no OAuth tokens, session cookies, payment details, or full webhook payloads.
- Rate limits on OAuth callback, checkout, portal, and API endpoints.
- Privacy policy, Terms, cancellation/refund policy, data export/deletion, and support contact before taking live payments.
- Use Stripe test mode and webhook test events before enabling live mode.

## Repository ownership transfer checklist

The repository has been transferred from `OwneraLabs/MCP-Security-Check-for-GitHub` to `rudimentall1/MCP-Security-Check-for-GitHub`. The following external settings must be verified; this document does not assert that they have already been changed:

1. Keep the repository name and default branch (`master`) unchanged.
2. In the PyPI project settings, verify or add the Trusted Publisher for:
   - Owner: `rudimentall1`
   - Repository: `MCP-Security-Check-for-GitHub`
   - Workflow: `publish.yml`
   - Environment: `pypi`
3. Keep `id-token: write` on the publish job and keep the dedicated `pypi` environment.
4. Verify the `pypi` GitHub environment exists and its protection rules are appropriate.
5. Check Dependabot, branch protection/rulesets, secrets, variables, Pages, webhooks, and external integrations after transfer.
6. Run Python Tests and Action Self-Test on the new canonical repository.
7. Test Trusted Publishing with the next release only after the publisher configuration is verified. If retaining more than one trusted publisher during transition, remove obsolete entries only after the new publisher succeeds.

## Decisions still required

- Confirm merchant eligibility and legal seller details for Stripe.
- Confirm the final monthly price and currency.
- Choose the production domain.
- Decide whether the first customer object is a personal workspace or a team workspace.
- Set privacy, retention, refund, and cancellation policies before live billing.
