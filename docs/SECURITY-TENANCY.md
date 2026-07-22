# OpenIDX Multi-Tenancy & the Tenant Trust Boundary

OpenIDX is **multi-tenant, enforced at the database**. Every tenant-owned
table carries an `org_id` and is protected by PostgreSQL **FORCE row-level
security (RLS)**. The tenant is resolved per request, stamped onto the pooled
database connection at checkout, and enforced by the database itself — not by
hoping every query remembers to filter. Access is **fail-closed**: a request
with no resolved tenant sees zero rows.

> **History.** OpenIDX was originally single-tenant by design, and earlier
> revisions of this document said so. That is no longer true: row-level
> multi-tenancy shipped (migration v37 established the FORCE-RLS belt; later
> migrations extended it to governance campaigns, ABAC, risk, and PAM tables).
> This document is the current, code-accurate trust-boundary statement.

## How tenant isolation is enforced

### 1. Every tenant table has `org_id` + a FORCE-RLS policy

Tenant-owned tables carry a non-null `org_id` and an RLS policy of the shape:

```sql
CREATE POLICY pol_<table>_org_scope ON <table>
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE  ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO openidx_app;
```

`FORCE ROW LEVEL SECURITY` means the policy applies **even to the table owner**,
so there is no privileged code path that silently bypasses it.

### 2. The runtime role is a non-owner

Services connect as `openidx_app`, which does **not** own the tables and cannot
disable RLS. A foothold that reaches the connection still cannot read across
tenants without the `app.org_id` GUC being set to that tenant.

### 3. The tenant is stamped on every connection at checkout

`internal/common/database/rls.go` sets the `app.org_id` (and, for the rare
cross-org maintenance path, `app.bypass_rls`) session GUC when a connection is
checked out of the pool, from the tenant resolved for the current request. No
service module has to remember to add a `WHERE org_id = …` clause — the database
enforces it. (Queries still carry an explicit `org_id` predicate as defense in
depth; see the CI gate below.)

### 4. The tenant is resolved per request

`internal/common/middleware/tenant_resolver.go` derives the tenant from, in
order, the request subdomain, the authenticated JWT, or the `X-Org-ID` header,
and places it in the request's org context (`orgctx`). If none resolves, the
request has no tenant and RLS yields zero rows — **fail-closed**.

### 5. A CI linter makes it un-bypassable by construction

`tools/orgscope` is a static analyzer wired as a **merge-blocking required CI
check**. It fails the build on any query against a tenant table that lacks an
`org_id` predicate, unless the call site is explicitly annotated
`//orgscope:ignore <reason>`. Every service ships an `orgscope_test.go`, and a
dedicated cross-org integration test (`test/integration/cross_org_test.go`)
asserts that one tenant cannot read another's data.

## Cross-tenant (install-wide) operations

Some background work is legitimately install-wide — directory-sync pollers, the
session-expiry sweeper, the Ziti reconciler, certification schedulers. These run
under an explicit, audited bypass:

- They set `app.bypass_rls = on` via the documented `WithBypassRLS` helper, or
  iterate tenants explicitly and set `app.org_id` per tenant.
- Each such site is annotated `//orgscope:ignore <reason>` so the bypass is
  visible in code review and to the CI linter.

The bypass is deliberate and narrow; the default for all request-path code is
tenant-scoped and fail-closed.

## What multi-tenancy covers

| Layer | Tenant isolation |
|---|---|
| Database schema | Enforced — `org_id` + FORCE RLS on tenant tables |
| Application services | Enforced — `app.org_id` stamped per connection; queries carry `org_id` |
| Authorization / governance | Scoped — campaigns, certifications, ABAC, SoD, and risk policies carry `org_id` |
| Audit | Scoped — `audit_events` is org-scoped, including Elasticsearch search |
| CI / tests | Enforced — `orgscope` merge gate + cross-org integration test |

## Federation vs. multi-tenancy

Multi-tenancy (per-`org_id` isolation) is distinct from **federation** (one
tenant trusting several upstream identity providers). Both are supported and
composable: within a single tenant, multiple IdPs can be registered in
`identity_providers`, and their users land in the same tenant-scoped `users`
table distinguished by `provider`. Federation happens inside a tenant boundary;
it does not cross one.

## Known follow-ups

Tenant data isolation is enforced as described above. Some cross-cutting
concerns are still being tightened tenant-by-tenant and are tracked in the gap
register ([`docs/MARKET_GAP_ANALYSIS_2026.md`](./MARKET_GAP_ANALYSIS_2026.md)):

- **Per-org signing keys.** OAuth/OIDC token signing currently uses one key set
  per install; per-tenant signing keys are a future enhancement.
- **Per-org rate-limit budgets.** The auth-surface rate limiter is being moved
  toward per-tenant budgets so a noisy tenant cannot consume a shared allowance.
- **Per-org Ziti overlay scoping.** The ZTNA plane is being namespaced per tenant
  (the "OSS OpenZiti multi-tenant console" work) for delegated-admin / MSP
  deployments.

## Deployment topologies

Both models are supported:

- **Shared install, many tenants (multi-tenant SaaS / MSP).** One database, one
  Redis, one OpenIDX deployment, tenants isolated by `org_id` + FORCE RLS. This
  is the model this document describes.
- **One install per tenant (dedicated / sovereign).** For customers who require
  physical isolation (a dedicated database, region, or SOC 2 boundary per
  tenant), the Helm chart and Terraform module under `deployments/` make
  per-tenant installs straightforward. This is a positioning choice, not an
  architectural limit.

## When this document is wrong

If a future PR changes the tenant boundary — for example, adding per-tenant
signing keys or per-tenant Ziti scoping — update this document to match. It is
the project's official trust-boundary statement; keep it code-accurate.
