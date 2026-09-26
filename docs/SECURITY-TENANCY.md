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

### 5. Tokens are bound to their organization

The tenant decides which rows a request sees; the token decides which roles
the caller holds, and those are their roles in one organization. Every access
token therefore carries `org_id`, the organization it was minted in, and every
API validator checks it against the organization the request resolved to:

- A token presented to a request for another organization is refused with
  `403`, whether that organization came from `X-Org-Slug` or from the
  default-org fallback. The same holds for an API key, whose organization is
  the key's own (the default organization for a key that records none).
- A token with no `org_id` is refused with `401`; signing in again or
  refreshing replaces it.
- A platform admin may act in another organization, by `X-Org-Slug` (the
  console's organization selector) or `X-Org-ID`. Where the resolver runs
  after authentication (admin-api), every such crossing writes a
  `platform_admin_cross_org_access` row to the target organization's audit
  trail.

A platform admin is a user holding the `super_admin` role in the install's
default organization (`00000000-0000-0000-0000-000000000010`): the token's
signed `org_id` names that organization and its roles include `super_admin`.
Roles are created per organization, so a `super_admin` role held in any other
organization is that organization's role and grants nothing outside it; the
identity API refuses to create a role with that name, or rename one to it,
outside the default organization. The same rule decides who lists, creates
and administers every organization through the organization API.

`organizations` and `organization_members` span the install, outside the RLS
belt, and so do `tenant_branding`, `tenant_settings` and `tenant_domains`,
which the login page reads before any organization is resolved. The APIs over
them keep organizations apart themselves. An organization's record and member
list are read by its members, in any role, and by a platform admin; its
branding, settings and custom domains (`/api/v1/tenants/{orgId}/...`) by the
administrators of the organization the request resolved to and by a platform
admin; anyone else gets the `404` an unknown id gets. Only a platform admin
creates an organization. An organization's owners and admins rename it; its
plan, status and limits are the install's decisions and only a platform admin
changes them. An owner or admin who tries gets `403`, and nothing of the
request is applied. An organization's members are its own users
(`users.org_id`) in a role it grants: `owner`, `admin` or `member`. Its owners
and admins add only its users, and a user of another organization gets the
`404` an id that names no user gets; a platform admin may add any user. Only an
owner or a platform admin grants the owner role or changes or removes an
owner's membership, and an organization keeps at least one owner.

A verified custom domain decides which organization's branding, custom CSS
included, the login page served at that host shows. A claim to a domain is
verified only by DNS: the TXT record `_openidx-challenge.<domain>` must hold
`openidx-domain-verification=<token>`, where the token is the one the claim was
given when it was added. Nothing sent with the request stands in for the
record, for a platform admin either. An unverified claim holds nothing, so any
number of organizations may claim the same domain, and a squatter's claim does
not keep the domain's owner out. One claim to a domain can be verified, and
verifying it removes the other organizations' unverified claims.

Tables under the belt give the same answer. A route that names one record of
another organization finds nothing and answers `404`, as it does for an id
that does not exist. The OAuth client routes (`/api/v1/oauth/clients/{id}`)
look the client up before they read the body or change anything, so an update,
a secret regeneration or a delete aimed at another organization's client does
not report a failure or a success it did not have.

Dynamic client registration (`POST /oauth/register`) is opened by one initial
access token for the whole install, so it registers clients in one
organization only: `DCR_ORG_ID`, or `DEFAULT_ORG_ID`. The token cannot pick
another organization through `X-Org-Slug` or a tenant's host.

### 6. A CI linter makes it un-bypassable by construction

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

## Install-wide settings

Some settings exist once for the whole install rather than once per
organization: the `system_settings` rows (SMS delivery, the passwordless
defaults, the OpenZiti controller connection, the BrowZer domain, the APISIX TLS
switch), the OAuth signing keys, the shared IP deny-list and error catalog, the
platform TLS certificate and key, and the self-heal loop's controls. Changing
one of them changes it for every organization.

Changing them needs an **administrator of the default organization**: a user
who holds `admin` or `super_admin` in the install's default organization
(`00000000-0000-0000-0000-000000000010`). Their own organization
(`users.org_id`, read from the database rather than from the request) must be
that organization, and so must the organization of the token or API key they
present, whose roles hold there only. `DEFAULT_ORG_ID` does not change who that
is: it names the organization a request with no tenant signal falls back to,
and nothing else. On a single-organization install that is every
administrator. An administrator of any other organization is refused with
`403 {"error": "platform administrator required"}`, and so is a read of the two
settings that carry credentials, the SMS provider and the OpenZiti controller
connection. The rule is in `internal/common/middleware/platform_admin.go`.

The default organization carries two rules, and they are not the same one.
Acting in another organization, listing every organization and creating one
need `super_admin` held there: a platform admin. Changing an install-wide setting
needs `admin` or `super_admin` held there. Every platform admin can change
install-wide settings; an `admin` of the default organization without
`super_admin` can change them and still cannot act in any other organization.

## Shared proxy surfaces

The access proxy serves every organization's applications from one listener,
and BrowZer from one set of nginx files, so what one organization's
administrator writes into a route reaches them. A host belongs to the one
enabled route that serves it, in the whole installation: the proxy,
forward-auth, the BrowZer configuration and the edge routes all find a route by
its host exactly, and every API that puts a route on a host (routes, quick
create, bulk create, app publishing, Ziti import, BrowZer on a service, the
BrowZer domain) answers 409 when another enabled route already serves it. The
first organization to route a host holds it; another organization is told only
that the host is routed elsewhere. There is no proof of domain ownership, so an
organization can hold a host before its owner routes it, and an operator
settles that by disabling the route (migration v211, `internal/access/route_host.go`).
A proxy session is good on the
host whose sign-in set its cookie and on no other host, whichever
organization's route that is, and it belongs to the route it was signed in on
and that route's organization: it is listed, revoked and continuously verified
there, and it is not accepted on another organization's route should the host
pass to one. The proxy follows a `redirect_url` only to a path
on the same host, to the access service's own host, or to a host of the
organization's own routes, where the organization is the one that owns the
route serving the request's host. The nginx configuration generated for
BrowZer takes a route only when its host, path, landing path and upstream are
plain values that nginx cannot read as syntax
(`internal/access/browzer_config_values.go`).
## The OpenZiti controller

One OpenZiti controller serves every organization on an install. Its services,
identities, policies, configs, terminators and sessions have no organization
of their own, so the access service decides what each caller sees of it. Three
mirror tables under the RLS belt record who owns what: `ziti_services` (by the
controller's id and by name, which the controller keeps unique),
`ziti_identities` and `ziti_service_policies`. An object that none of them
gives to an organization is the install's.

- Reading an organization's part of the fabric needs the operator tier. An
  install administrator, as above, sees the whole controller. Anyone else sees
  their organization's services, the configs and terminators of those
  services, its service policies, and the sessions between its identities and
  its services.
- Reading what no organization owns needs an install administrator: the edge
  routers and their policies, the authentication policies and JWT signers, the
  config types, the fabric metrics, the reconciler and network-setup state,
  the BrowZer bootstrapper, the AI ledger, discovery of unmanaged services, the
  governance-policy syncs and the PAM broker's bindings.
- The status probes (`/ziti/status`, `/health/ziti`, `/health/integrations`
  and `/ziti/browzer/status`) stay open to any signed-in user. They say whether
  the overlay is up and count the organization's own services and identities.
  The controller's version, addresses and error text go to an install
  administrator only.
- A write to something the organization owns needs the admin role and reaches
  only the organization's own objects: ending one of its sessions, or every
  session of one of its identities, removing a terminator of one of its
  services, turning BrowZer on or off for one of its services, rotating one of
  its certificates. Another organization's object, taken by its id, gets the
  `404` an unknown id gets. An install administrator reaches any.
- A write to something no organization owns needs an install administrator:
  enrolling an edge router, reconnecting the controller, the edge-router,
  authentication and JWT-signer policies, raw configs, the AI analysis, its
  anomalies and quarantine, the governance-policy syncs, and importing a
  service no organization manages.

The rules are in `internal/access/ziti_scope.go`.

## What multi-tenancy covers

| Layer | Tenant isolation |
|---|---|
| Database schema | Enforced — `org_id` + FORCE RLS on tenant tables |
| Application services | Enforced — `app.org_id` stamped per connection; queries carry `org_id` |
| Tokens and API keys | Bound — accepted only in their own organization, except a platform admin's |
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

Tenant data isolation is enforced as described above, with one known gap:
the application's own database role can set `app.bypass_rls`, so a single
SQL injection could lift the row-level-security boundary
([#964](https://github.com/mhmtgngr/openidx/issues/964) moves the bypass to a
dedicated role). Some cross-cutting concerns are still being tightened
tenant by tenant. Their priority is set in
[ROADMAP.md](https://github.com/mhmtgngr/openidx/blob/main/ROADMAP.md); the
archived readiness guide
([`docs/archive/PROJECT-READINESS-GUIDE.md`](https://github.com/mhmtgngr/openidx/blob/main/docs/archive/PROJECT-READINESS-GUIDE.md))
records how they were found:

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
