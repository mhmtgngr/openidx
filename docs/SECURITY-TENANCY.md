# OpenIDX is Single-Tenant by Design

This document explains a deliberate scope choice in OpenIDX that is
not a bug, and which the v1.0 plan made explicit: **one OpenIDX
install is for one organization**. The identity service, the OAuth
service, and every data table they touch live under a single
trust boundary — the operator who runs the install.

If you are building a multi-tenant SaaS on top of OpenIDX, you are
either running one OpenIDX install per tenant (supported), or
building tenant isolation in a layer above us (your engineering
choice). OpenIDX itself does not enforce per-tenant data isolation
at the database row level.

## What this means in practice

### Data layer

`internal/identity/service.go` and every other service module take a
`*pgxpool.Pool` and run queries with no implicit tenant scoping. There
is no `tenant_id` column on `users`, `roles`, `sessions`,
`oauth_clients`, `audit_events`, or any of the other core tables. Every
admin can read every row. Every authenticated user with the right role
can act on every other user in the install.

This is intentional. Retrofitting row-level multi-tenancy onto the
data model is a large epic with significant performance and migration
cost, and the OSS / per-customer install model does not require it.

### Identity layer

Roles and permissions in OpenIDX are global to the install. There is
no concept of "tenant administrator" vs "global administrator" — an
admin role grants the same access in every code path. Federation
identities (SAML, OIDC) all land in the same `users` table; the only
distinction between, say, two SAML IdPs is the row's `provider`
column, not a tenant boundary.

### Access control layer

OPA policies and access reviews are also global. An access review
named "Q1 2026 user-access" reviews every user in the install. There
is no per-organization scoping on review campaigns, certifications,
SoD policies, or risk-based MFA policies.

### Audit layer

`audit_events` records actions across the entire install. There is
no per-tenant audit channel. A compliance officer with read access to
the audit table can see every action by every user.

## What the project *does* support

### Federation across multiple identity sources

Many organizations want OpenIDX to be the single sign-on point in
front of multiple identity providers (one corporate AD, several SAML
IdPs for acquired entities, a couple of social providers for
contractors). This works: each IdP is registered separately in
`identity_providers`, users from each are stored in the same `users`
table with `provider` distinguishing them, and the OAuth service
mints the same shape of access token regardless of upstream IdP.

That is **federation**, not multi-tenancy. Every federated user
shares the audit log and the role catalog.

### Application catalog with per-app authorization

`internal/access` and `internal/governance` let an admin publish
multiple downstream applications, each with its own access policy
(who can reach it, which device-trust posture is required, etc).
That gives the install many tenants of *applications*, not of
*organizations*.

### Per-customer deployments

If your operating model is "one organization per OpenIDX install,"
everything works as advertised. This is the supported topology —
SOC2 boundary lines align with the install, JWT signing keys are
unique per install, the database belongs to the customer, etc.

## What the project does *not* support — and why

We do not currently support:

- **Per-tenant data isolation at the row level.** Adding a
  `tenant_id` column to every table, propagating it through every
  query, and enforcing it via Postgres RLS is a sizable epic. Until
  it lands, do not run two unrelated organizations against the same
  install and assume they cannot see each other's data.

- **Per-tenant signing keys.** JWT and ID-token signing uses one key
  per install. Rotating the key affects every tenant simultaneously.

- **Per-tenant rate limits.** The brute-force / IP-rate-limit
  middleware operates against the install as a whole; a noisy tenant
  can consume the shared budget.

- **Per-tenant audit isolation.** The audit table is shared. There is
  no built-in way to give one tenant's compliance officer audit-read
  access without exposing every tenant's events.

These items are all on a list called "multi-tenant SaaS isolation" in
the v1.0 plan. They are **explicitly out of scope** for v1.x — the
release-engineering work has been about making the single-tenant
posture credible and well-instrumented. The multi-tenant story is a
v2 epic, not a follow-on patch.

## If you really need multi-tenancy

The supported pattern is **one OpenIDX install per tenant**. Helm
chart + Terraform module (under `deployments/`) make this
straightforward: spin up a fresh database, a fresh Redis namespace, a
fresh OpenIDX deployment, point your gateway at it. Each install gets
its own JWT signing key, its own audit log, its own admin set, and
its own SOC2 boundary line — which is the original ask in most
"I need multi-tenancy" conversations.

If your model genuinely requires shared infrastructure (one DB, one
Redis, one OpenIDX, many tenants), please open an issue describing
the constraint that makes per-tenant installs unworkable. Multi-
tenant SaaS isolation will land as its own major-version effort when
the demand for it is concrete.

## Where this assumption is enforced (or not)

| Layer | Single-tenant assumption is… |
|---|---|
| Database schema | Not enforced — no `tenant_id` columns. |
| Application services | Assumed — no scoping in queries. |
| Authorization | Assumed — roles are global. |
| Audit | Assumed — shared table. |
| Documentation | Stated here and in [SECURITY-HARDENING.md](./SECURITY-HARDENING.md). |
| CI / tests | Not checked — the integration suite runs against a single install. |

The project deliberately does not add half-measures (e.g., a
`tenant_id` column that some queries use and others ignore) because a
silent inconsistency is worse than an explicit single-tenant scope.

## When this document is wrong

If a future PR adds genuine multi-tenancy — for instance, row-level
security on `users` with a `tenant_id` column propagated through
every query and verified by tests — this document is the place to
say so. Until then, please treat the contents above as the project's
official trust-boundary statement.
