# OpenIDX v2.0 Multi-tenancy Design

**Status:** Draft. Approved at architectural level 2026-06-11.
**Supersedes when shipped:** `docs/SECURITY-TENANCY.md` (single-tenant
trust boundary statement).

This document is the design for the v2.0 epic that the v1.0 plan
deferred. It is the planning artifact, not the implementation. Each
milestone below ships as its own minor release with its own PR series.

## What we are building

OpenIDX today is single-tenant: one install, one organization, one
audit log, one role catalog, one signing key. The v1.0 plan said this
was intentional and that lifting it would be a v2 epic. This document
is that epic.

We are turning OpenIDX into a multi-tenant platform where one install
can host multiple unrelated organizations with mutually-isolated data,
isolated audit, isolated rate-limit budgets, per-org role catalogs, and
admin UIs scoped to a single organization unless the actor is a
platform admin.

We are not building self-service signup, billing, hard quota
enforcement, per-tenant signing keys, or schema/database-per-tenant.
Those are deliberately deferred to v2.1 and beyond.

## What is already there (and why we are not starting from scratch)

The v1.0 trust-boundary statement in `SECURITY-TENANCY.md`
under-describes the codebase. Verified state of the repo at the time
this document was written:

| Surface | State |
|---|---|
| `organizations` table | Exists with `slug`, `domain`, `plan`, `status`, `max_users`, `max_applications`, `settings JSONB` |
| `organization_members` join table | Exists with role enum (default `member`) and `UNIQUE(organization_id, user_id)` |
| `internal/organization/service.go` | CRUD + member management API already implemented |
| `users.org_id`, `groups.org_id`, `roles.org_id` | Columns exist (NULL-able), not enforced anywhere |
| `oauth_clients.tenant_id` | Separate parallel column with `'default'` fallback — predates `org_id` convention |
| `internal/admin/tenant_branding.go` | Per-org branding already in admin API |
| `internal/admin/email_templates.go` | Per-org email templates already in admin API |

What is missing:

| Gap | Severity |
|---|---|
| ~30+ core tables have no `org_id` (audit_events, sessions, oauth_*_tokens, applications, mfa_*, access_reviews, approval_policies, known_devices, …) | Blocking |
| No query in the codebase filters by org scope | Blocking |
| No tenant-resolution middleware | Blocking |
| Two parallel concepts (`org_id` vs `oauth_clients.tenant_id`) | Inconsistency |
| No platform-admin vs org-admin distinction | Blocking for compliance reads |
| No per-tenant JWT `iss` claim | Blocking for token isolation |
| No per-tenant rate limit partitioning | Soft (DoS amplifier across tenants) |
| No per-tenant audit isolation | Blocking for SOC2-style separated compliance |

The v2.0 epic finishes the existing scaffolding rather than building
from scratch. That changes the cost calculation in the v1.0 plan
(which assumed a green-field retrofit).

## Architectural decisions

### Decision 1 — Tenant resolution

A request resolves to an `org_id` via three mechanisms, checked in
order:

1. **Subdomain** (browser): `acme.openidx.io` →
   `organizations.slug = 'acme'`. Requires wildcard TLS cert + DNS at
   deploy time. Gateway sets `X-Org-Slug`; middleware resolves to
   `org_id`.
2. **JWT `org_id` claim** (API): all v2 tokens carry the org_id of
   the subject's session. Token issuance enforces it from the OAuth
   authorize flow's resolved tenant.
3. **`X-Org-ID` header** (admin tooling / tests): only honored when
   the caller is a platform admin. Lets ops/compliance read
   cross-org without ambiguity.

If none resolve, the request is rejected (no implicit "default").
Existing single-tenant installs get a `'default'` org during upgrade
(see Decision 6) and the gateway is configured to inject its slug for
non-subdomained traffic during the upgrade window.

### Decision 2 — Isolation enforcement

Defense in depth: **app-layer filter + Postgres RLS belt**.

- **App-layer**: every service method takes an `OrgID` from
  `context.Context` (set by the tenant-resolution middleware) and
  every INSERT/SELECT/UPDATE/DELETE filters by it. This is the
  primary mechanism, the one tests verify, the one developers
  reason about.
- **RLS**: Postgres policies on every scoped table enforce the same
  filter at the row level using a per-connection
  `SET LOCAL app.org_id = '<uuid>'`. The middleware sets it on
  checkout from the pool. If app-layer forgets a filter, RLS still
  refuses to return another tenant's rows.

We reject single-layer approaches:

- **App-layer only** is what the `SECURITY-TENANCY.md`
  "no half-measures" passage warned against — a forgotten filter is
  silent data leak in production.
- **RLS only** is fragile: `session_user` role management, pg_dump
  semantics, EXPLAIN that doesn't show the filter — debug cost is
  high and the app layer ends up needing to know about it anyway.

### Decision 3 — Naming unification

`org_id` everywhere. `oauth_clients.tenant_id` gets renamed to
`oauth_clients.org_id` and backfilled from the existing column's
value (mapping `'default'` to the default org's UUID). The
`TenantID` field on `internal/oauth/client.go` becomes `OrgID`.
This is breaking for any external caller; we ship it as a v2.0
breaking change with a deprecation note in the changelog and a
6-month compatibility window where both fields are accepted in
request bodies.

### Decision 4 — Token signing

One signing key per install, with a per-tenant `iss` claim
(`https://acme.openidx.io` for tenant `acme`). Verifiers check `iss`
against the org slug. We deliberately do not introduce per-tenant
signing keys in v2.0 because:

- Key management becomes O(N tenants) for rotation, revocation,
  JWKS distribution. Significant ops cost.
- `iss` claim already provides token-binding to a tenant; a token
  from one tenant cannot be used to access another tenant's
  resources because the resolver compares the resolved org to the
  token's `iss`.
- If a customer with shared infra needs cryptographic
  per-tenant isolation, that ships as v2.1.

### Decision 5 — Role model

Two role planes:

- **Platform admin** (`users.is_platform_admin BOOLEAN`): can read
  all orgs, can bypass org filters, can act as ops or
  cross-tenant compliance. Audit log records every cross-tenant
  read with `platform_admin: true` and the actor's user_id.
- **Org-scoped role** (`organization_members.role`): existing
  column, expanded enum: `owner`, `admin`, `member`, `viewer`,
  `compliance_reader`. The last one is new — read-only access to
  the org's audit events without write capability anywhere else.

A platform admin is not implicitly an admin of every org; they get a
banner in the admin UI saying "you are acting as platform admin in
<org>" and the action is logged with that flag set.

### Decision 6 — Existing install upgrade

Three-step migration sequence runs on first startup of v1.6.0:

1. **v34**: add `org_id UUID` (NULL-able) to every core table.
   Includes an `idx_<table>_org_id` index on each.
2. **v35**: create the `'default'` organization if there are
   existing rows in `users`, set every NULL `org_id` row to the
   default org's UUID. Idempotent: if no users exist (fresh
   install), nothing is created — operator runs through
   normal v2.0 onboarding.
3. **v36**: `ALTER TABLE … ALTER COLUMN org_id SET NOT NULL` +
   `ADD CONSTRAINT … FOREIGN KEY (org_id) REFERENCES
   organizations(id) ON DELETE RESTRICT`. RLS policies are added
   in this migration as well.

Operators do nothing. A v1.x install with one organization's worth
of users wakes up as a v1.6.0 install with one organization named
`default`. They can rename the default org in the admin UI at their
leisure.

### Decision 7 — Database isolation model

Single PostgreSQL database, single schema, row-level isolation.

We reject schema-per-tenant and database-per-tenant. Schema-per
multiplies the migration surface by tenant count; database-per
multiplies it further and breaks shared infra primitives (e.g.,
audit roll-ups across the install). The OSS install model is
"one install, few tens of tenants," not "one install, ten
thousand tenants" — schema/db-per-tenant is an answer to a
problem we do not have.

## Milestone plan

Each milestone is its own minor release with its own PR series.
No milestone ships partial enforcement — the test for "are we done
with milestone N?" is "would shipping this leak data?"

### v1.6.0 — Foundation (schema + context plumbing, no enforcement)

- Migration v34: add `org_id` to all missing core tables (NULL)
- Migration v35: backfill `'default'` org
- Migration v36: NOT NULL + FK constraint + RLS policies created
  but **not yet enabled** (set to `PERMISSIVE` with `USING (true)`)
- `OrgContext` carried via `context.Context`; setters and getters
  in `internal/common/orgctx`
- Tenant-resolution middleware: subdomain → JWT claim → header
- Static helper (Go AST walk + lint integration) that flags
  service-layer `db.Query` calls without an `org_id` filter
- Tests: every existing table has `org_id` populated; resolution
  middleware resolves correctly across all three sources

Ship gate: install upgrades cleanly, all v1.5 functionality continues
working, no enforcement yet.

### v1.7.0 — App-layer enforcement

- Service-by-service refactor: every query reads `org_id` from
  context and filters by it. Inserts populate it.
- Platform admin bypass + audit log entry on every bypass
- Per-tenant JWT `iss` claim
- Admin UI tenant selector
- CI lint promotes "missing org filter" from warning to error
- Tests: cross-org access via a token returns 404 (not 403, to
  prevent enumeration); platform admin can read across orgs

Ship gate: a token issued for org A cannot read org B's data via
any service method.

### v1.8.0 — RLS belt + per-org primitives

- Postgres RLS policies activated (replace `USING (true)` with
  `USING (org_id = current_setting('app.org_id')::uuid)`)
- Connection pool middleware sets `SET LOCAL app.org_id` on
  checkout; clears on return
- Per-org rate-limit buckets (partition existing limiter)
- Per-org audit reader role (`compliance_reader`)
- Per-org branding UI completion (already half-built in admin)
- Single-tenant → multi-tenant upgrade runbook
- Tests: integration suite runs with two tenants, asserts neither
  can see the other's anything even with app-layer bug injected
  (deliberately drop the filter, RLS catches it)

Ship gate: RLS holds even when app-layer is intentionally broken.

### v2.0.0 — GA

- Load test: 50 tenants × realistic traffic, verify no regression
- `SECURITY-TENANCY.md` rewritten to describe v2.0 multi-tenant
  posture
- This design doc moves to `docs/archive/`
- Pen-test pass on tenant isolation (external)
- Production-readiness audit (similar shape to v1.0 P0 sweep)

Ship gate: an external pen tester cannot escape tenant isolation
in any documented way.

## Out of scope for v2.0

These are real asks that will come up; the answer for v2.0 is
"not yet."

- **Per-tenant signing keys** — re-evaluate for v2.1 if customers
  ask. `iss` claim is sufficient for the threat model v2.0 ships.
- **Schema/database-per-tenant** — would conflict with the RLS
  approach and is not justified by current scale targets.
- **Self-service tenant signup UI** — admin-create only for v2.0.
  Self-service is a v2.2 concern that depends on billing.
- **Cross-tenant federation** — one tenant SSO'ing to another is
  out of scope; no compelling internal request yet.
- **Hard quota enforcement** — `max_users` and `max_applications`
  columns exist but remain soft (logged-only) in v2.0. Hard
  enforcement comes with billing.
- **Billing / metering** — entirely deferred.
- **Tenant-aware OPA policies** — OPA policies become per-tenant
  in v2.1; v2.0 keeps them global with `org_id` in the input.

## Risk register

| Risk | Mitigation |
|---|---|
| A forgotten `org_id` filter leaks data | App-layer lint + RLS belt; integration test deliberately drops a filter and asserts RLS catches it |
| Migration v35 backfill is wrong for installs with no users | Idempotent: only creates `'default'` if a user exists. Fresh installs do v2.0 onboarding instead |
| `oauth_clients.tenant_id` rename breaks external integrations | 6-month compatibility window accepting both fields in request bodies; deprecation note in v1.6.0 release notes |
| RLS performance regression | Benchmarks gate v1.8.0; measure p99 query latency before/after RLS turn-on |
| Platform admin role becomes a backdoor | Every cross-org read writes a distinguished audit entry with the platform admin flag and actor user_id; admin UI shows persistent banner |
| Connection pool resetting `SET LOCAL` correctly | Pool middleware tests assert checkout sets it, return clears it, no cross-request bleed |
| Existing tests assume "default" context implicitly | v1.6.0 ship gate: full existing test suite passes with backfilled default org |
| One milestone ships partial enforcement and looks safe | Hard rule per-milestone ship gate stated above; partial milestones are not merged |

## Sizing

Realistic estimate: 4–6 weeks of focused work spread across many
small PRs. Not a single PR. Approximate split:

- v1.6.0 (foundation): ~10 PRs, ~1.5 weeks
- v1.7.0 (app-layer enforcement): ~20 PRs (one per service area),
  ~2 weeks
- v1.8.0 (RLS + primitives): ~10 PRs, ~1 week
- v2.0.0 (GA hardening): ~5 PRs, ~0.5 weeks

Each PR remains small and reviewable. CI stays trustworthy.

## When this document changes

This document is the source of truth for v2.0 design decisions
until v2.0 ships. If implementation discovers a decision was
wrong, the PR that changes course also updates this document.
Diverging the code from this doc silently is a process bug; we
treat the doc as part of the artifact.

When v2.0 ships, this document moves to `docs/archive/` and
`SECURITY-TENANCY.md` is rewritten to describe the new posture.
