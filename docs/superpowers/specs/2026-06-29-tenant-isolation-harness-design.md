# Tenant-isolation test harness (v2.0 GA sub-project 1) — design

## Context

v2.0.0's ship gate is "an external pen tester cannot escape tenant isolation in
any documented way." The automated, repeatable proxy for that gate is a
tenant-isolation test suite. Much of it already exists in
`test/integration/cross_org_test.go` (run via `make test-integration`, behind the
integration build tag):

- **`TestRLSBelt`** — runs read assertions on a connection from a dedicated
  **NOSUPERUSER** role (`rlsRolePool`), reproducing production (a superuser/
  BYPASSRLS connection would make RLS vacuous). Asserts: scoped-to-A can't see
  B's rows (by `org_id` and by `id`); scoped-to-B sees its own; **no scope →
  0 rows (fail-closed)**; **bypass → sees across orgs**. (`users` only.)
- **`TestCrossOrgIsolation`** — HTTP: same-org → 200; cross-org (via
  `X-Org-Slug`) → **404 (anti-enumeration)**; platform-admin `X-Org-ID`
  cross-org read is **audited**.
- Harness helpers: `seedOrg`, `seedUserInOrg`, `bypassExec`, `rlsRolePool`,
  `apiRequestWithOrg`/`apiRequestWithOrgID` (set `X-Org-Slug`/`X-Org-ID`).

So the row-level read foundation, one HTTP read surface, and the bypass-audit are
proven. This sub-project closes the remaining gaps. **Settled scope: focused
high-value** (write-path + spoofing-rejection + belt-breadth), not an exhaustive
per-service HTTP matrix — the row-level belt already guarantees every service.

### A correctness note that shapes Component 2

The existing HTTP tests hit services **directly** (`identityURL=:8001`,
`oauthURL=:8006`) and set `X-Org-Slug` on the service request — they *simulate*
the gateway. Services **trust** `X-Org-Slug` because in production the **gateway**
is the boundary that strips any client-supplied `X-Org-Slug` and re-derives org
from the subdomain/JWT (`internal/gateway/middleware` `OrgSlugHeader`). So a
spoofing test that sends a forged header **straight to a service is not a
meaningful negative** (the service trusts it by design). The spoofing negatives
must route **through the gateway (`:8008`)** to exercise the strip. Likewise, a
**spoofed JWT `org` claim is not attacker-achievable** — the token is signed by
the oauth service; a client cannot forge its org. That vector is covered by
signature validation, not a header strip, so it is **not** part of this suite
(noted to avoid a vacuous test).

## Design

All additions live in `test/integration/cross_org_test.go` (+ a small
gateway-routed helper in `helpers_test.go`), reuse the existing harness, and are
gated by the same integration build tag.

### Component 1 — Write-path RLS belt (extend `TestRLSBelt`)

On the NOSUPERUSER `rlsRolePool` connection, with the session scoped to org A
(`set_config('app.org_id', A, false)`):

- **INSERT cross-org is rejected by `WITH CHECK`:** inserting a `users` row with
  `org_id = B` returns an error (RLS `WITH CHECK` violation); the same insert
  with `org_id = A` succeeds. Asserts a tenant cannot plant rows in another org.
- **UPDATE / DELETE cannot reach across orgs:** `UPDATE users SET … WHERE id =
  <userB>` and `DELETE FROM users WHERE id = <userB>` each report **0 rows
  affected** under A-scope (the `USING` clause hides B's row); the same under
  B-scope (or bypass for cleanup) affects 1. Asserts writes can't mutate another
  org's rows.

Seeding/cleanup of B's row uses the existing `bypassExec`/seed helpers. Focused
on `users` (its column set is trivial); the UPDATE/DELETE-0-rows pattern is the
generally-applicable guarantee.

### Component 2 — Spoofing-rejection negatives (new `TestCrossOrgSpoofing`, via the gateway)

Add a gateway-routed helper (`gatewayURL = envOrDefault("GATEWAY_URL",
"http://localhost:8008")`) that issues a request through the gateway with
arbitrary headers. **Skip the test if `:8008` is unreachable** (the integration
CI may not start the gateway; the box does) — same skip-with-guidance pattern the
suite already uses for a missing DB.

Authenticated as an **org-A, non-platform-admin** user, against an endpoint the
gateway proxies:

- **Forged `X-Org-Slug: <orgB>` → stripped:** the gateway drops the
  client-supplied header and re-derives org (from the JWT/subdomain), so the
  request is scoped to A — a read of org B's resource returns **404**, and a list
  returns only A's rows (never B's). Proves `OrgSlugHeader` strips client input.
- **Forged `X-Org-ID: <orgB>` (non-admin) → not honored:** same outcome (the
  audited `X-Org-ID` bypass is platform-admin-only; a normal user's forged
  `X-Org-ID` grants no cross-org access).

Both assert the *negative* (no B data, 404/own-only) — the security boundary
holds at the entry point.

### Component 3 — Belt breadth (parametrize the read-belt)

Parametrize the existing `TestRLSBelt` read assertions over ~4 representative
scoped tables — `users`, `applications`, `oauth_clients`, `audit_events` — via a
table-driven loop: for each, seed one row in org A and one in org B (under
bypass), then assert scoped-to-A count of B's rows = 0 and bypass count = all.
Generic (needs only `org_id` + a seedable row per table), so it doesn't require
per-table column knowledge beyond a minimal insert. Confirms the guarantee isn't
an artifact of the `users` table alone.

## Testing / running

- `make test-integration` (the integration build tag) against the running stack
  (`make dev-infra` + services) — these need a real DB and, for Component 2, the
  gateway on `:8008`. The CI **Integration Tests** job runs the suite; the
  gateway-routed test self-skips if `:8008` isn't up there.
- Components 1 & 3 need only the DB + the NOSUPERUSER role (already provisioned
  by the harness); they run wherever `TestRLSBelt` runs today.

## Verification checklist

- `go vet ./test/integration/...` clean; the suite compiles under the integration
  build tag.
- On the box (full stack incl. gateway): write-belt rejects cross-org
  INSERT/UPDATE/DELETE; the gateway strips forged `X-Org-Slug`/`X-Org-ID`
  (cross-org read still 404 / own-only); the read-belt passes for all 4 tables.
- CI Integration Tests job stays green (gateway-routed test skips if `:8008`
  absent, with a logged reason).

## Out of scope

- Exhaustive per-service cross-org HTTP read/write matrix (the row-level belt
  already covers every service; revisit only if the pen-test finds a gap).
- The external pen-test engagement itself (vendor activity).
- The v2.0 load test, `SECURITY-TENANCY.md` rewrite, and design-doc archival
  (separate GA sub-projects).
- Testing a spoofed JWT `org` claim (signature-protected; not client-forgeable).
