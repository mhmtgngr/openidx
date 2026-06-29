# P0-2 — Bypass-wrap pre-tenant-resolution lookups against FORCE-RLS tables

## Context

The v1.8.0 cutover ran the app DB connection as the non-owner `openidx_app`
role (NOSUPERUSER, NOBYPASSRLS) so the migration-v37 restrictive RLS policies
actually bite. The policy is fail-closed:

```
app.bypass_rls = 'on'  OR  org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
```

A query against a FORCE-RLS table returns **zero rows** unless its ctx carries
either a resolved org (`app.org_id`) or bypass (`app.bypass_rls='on'`). Those
GUCs are set at pgx pool checkout (`internal/common/database/rls.go`) from the
query ctx; `orgctx.WithBypassRLS(ctx)` opts a query into cross-org reads.

**The defect (P0-2):** a class of lookups key off a *globally-unique credential,
host, or token* **before** the tenant org is known — so they legitimately carry
no `org_id` filter — but they were never marked `WithBypassRLS`. Under
`openidx_app` they fail closed. This was a **live regression** on the box: the
access reverse proxy resolved **0 routes** (`findRouteByHost` returned nothing),
API-key auth failed for every key, device-trust silently returned false, and
Ziti startup reads were truncated. Verified live: as `openidx_app` with no GUC,
`SELECT count(*) FROM proxy_routes` = 0 while the table holds 5 rows.

**Immediate mitigation already done:** the box was rolled back to the `openidx`
superuser (RLS inert, app-layer org filtering still active — the pre-v1.8
posture); the proxy + API-key auth are restored. Both env files retain the
`openidx_app` URL in a comment for re-cutover once this fix lands.

This spec is the **fix-forward**: bypass-wrap the complete enumerated set of
pre-resolution lookups so the box (and compose/prod) can re-cut-over to
`openidx_app` with RLS enforcing and nothing broken.

## Approach

**Per-site `WithBypassRLS`, not a blanket bypass role.** Running the whole access
service under a BYPASSRLS role was considered and rejected: the access service
also has genuinely org-scoped admin/CRUD endpoints (route/app management) that
run *with* org context, and blanket-bypassing throws away RLS enforcement there.
The pre-resolution set is bounded and fully enumerated (orgscope is green, so
every org-less query carries an `//orgscope:ignore`; the set was audited
exhaustively). Per-site wrapping is the minimal-blast-radius, honest fix.

Each wrapped lookup keys off a globally-unique value and reads `org_id` out of
the returned row exactly as it does today — bypass only restores visibility; it
does not change which row is selected (except `findRouteByHost`, see nuance).

### Three mechanisms

**1. Request / auth-path lookups → wrap the lookup ctx in `orgctx.WithBypassRLS`.**

| file:line | function | table | keys on |
|---|---|---|---|
| `internal/apikeys/service.go:321` | `ValidateAPIKey` | api_keys | `key_hash` |
| `internal/apikeys/service.go:462` | `updateLastUsed` | api_keys | `id` (from above) |
| `internal/access/service.go:2254` | `findRouteByHost` | proxy_routes | host (`from_url LIKE`) |
| `internal/access/service.go:1588` | `handleLogout` | proxy_sessions | `session_token` |
| `internal/access/service.go:1591` | `handleLogout` | proxy_sessions | `id` |
| `internal/access/service.go:2481` | `updateSessionActivity` | proxy_sessions | `id` |
| `internal/access/service.go:234` | `deleteAppTile` | applications | synthetic `client_id` |
| `internal/access/context_evaluator.go:81` | `buildAccessContext` | ziti_identities | `user_id` |
| `internal/access/device_trust.go:26` | `deviceTrusted` | known_devices | `user_id`+`fingerprint` |
| `internal/access/device_trust.go:53` | `ensureDeviceTrustRequest` | known_devices | `user_id`+`fingerprint` |
| `internal/access/ziti.go:461` | `forwardHTTPConnection` | users, user_roles, roles | ziti identity = user id |
| `internal/access/agent_api.go:484` | `bridgeDevicePostureResult` | ziti_identities | `agent_id` |
| `internal/access/agent_api.go:494/746` | `bridgeDevicePostureResult` / `loadIntegrityPolicy` | posture_checks | posture/check_type |
| `internal/access/app_publish.go:465` | `registerAccessProxyCallback` | oauth_clients | shared `access-proxy` client |
| `internal/access/health_checks.go` (~11 scans) | Integrity Doctor | proxy_routes, ziti_services, applications, oauth_clients, ziti_identities, users, policies, known_devices | install-wide diagnostic |

For request handlers, wrap the ctx used for the specific lookup (or, where a
helper does several install-wide reads such as the Integrity Doctor, wrap once at
the handler entry). Do **not** widen bypass beyond the pre-resolution lookup.

**2. Background roots that mint a fresh `context.Background()` (bypassing the
bypass convention) → wrap the root once.**

- `cmd/access-service/main.go:303` `zitiCtx` is created with
  `context.WithCancel(context.Background())` and is **not** bypass-wrapped (unlike
  the sibling `bootCtx`). It feeds `EnsureZitiServicesForRoutes`,
  `EnsureBrowZerRouterService`, `HostAllServices`, `getAdminUserID`, and the
  BrowZer config writers — all of which read FORCE-RLS tables. Wrap `zitiCtx` in
  `orgctx.WithBypassRLS` at creation (one line; fixes the whole cascade).
- `internal/directory/sync.go` `TriggerSync` mints a fresh bgCtx → wrap it so
  scheduled/triggered directory sync survives under `openidx_app`.
- `internal/access/unified_audit.go:292` and `internal/audit/stream.go:634/654`
  mint fresh background ctx for audit sync / webhook delivery → wrap.

**3. `internal/identity/webauthn.go:239` & `:306` → add `AND org_id = $2`
(defense-in-depth).** These login lookups (`users` by `username`) carry no org
filter and no bypass; they rely solely on the resolved-org GUC. The org *is*
resolved on the login path, so the correct fix is to **filter by org** (matching
`AuthenticateUser`'s `AND org_id=$2`), not bypass. This both fixes fail-closed
and adds a real isolation layer.

### `findRouteByHost` nuance

`findRouteByHost` matches `from_url LIKE '%host%'` … `ORDER BY priority DESC
LIMIT 1`. With bypass it sees every org's routes, so if two tenants ever
registered the *same* host it could mis-route. Hosts are the proxy's tenant
boundary (a subdomain maps to exactly one org), so this is safe today. Document
the host-global-uniqueness assumption in a code comment at the bypass site;
do not attempt per-org host scoping (there is no org context at this point — the
host is what resolves the org).

## Out of scope

- Cutting compose / `.env` / `docker-compose.prod.yml` over to `openidx_app`
  (P1; depends on this fix but is a separate change).
- The other audit P0s (P0-1 unsigned-JWT bearer, P0-3 init-db reconcile, P0-4
  APISIX key, P0-5 branch protection).
- Latent, currently-unwired cleanup jobs (`risk/alert.go` `CleanupOldAlerts`,
  `identity/passwordless.go` `CleanupExpiredPasswordlessSessions`) — note in code
  but not wired, so not failing today; fix if/when wired.
- Re-design of `findRouteByHost`'s `LIKE` matching (tracked separately).

## Testing / verification

**Integration test (the regression guard the audit flagged as missing).** In
`test/integration/cross_org_test.go`, on the NOSUPERUSER `rlsRolePool` connection
with **no** `app.org_id` set (reproducing pre-resolution):

- Seed (under bypass) an `api_keys` row + a `proxy_routes` row in org A.
- Assert that the production code path's queries return the row under
  `openidx_app` with no GUC — i.e. a `SELECT … WHERE key_hash=$1` and a
  `findRouteByHost`-shaped `from_url LIKE` both return 0 rows on a plain
  `rlsRolePool` query, and **1 row** once `app.bypass_rls='on'` is set. This
  pins the exact failure mode and proves bypass is the remedy.
- Reuse `seedOrg`, `bypassExec`, `rlsRolePool`. Self-skip if the DB/role isn't
  provisioned (existing harness pattern).

**Unit-level:** `go build ./...`, `go vet ./...`, `gofmt`, and the existing
`go test ./internal/access/... ./internal/apikeys/...` stay green. `go run
./tools/orgscope -fail ./internal` stays green (the `//orgscope:ignore`
directives are unchanged; bypass-wrapping doesn't add org-less SQL).

**Live re-cutover (on the box, after merge):**
1. Re-point both env files to the `openidx_app` URL (uncomment), restart all 8.
2. Confirm: `psm.tdv.org`/`netgraph.tdv.org` → 302 (route resolved), a bogus host
   → 404; an API key validates; access-service log shows clean Ziti startup (no
   "0 routes"/RLS-empty warnings); device-trust evaluates.
3. Confirm RLS still enforces for org-scoped reads (the existing `TestRLSBelt`
   data-plane assertions remain true under `openidx_app`).
4. Decide: leave on `openidx_app` (RLS enforcing) or revert pending more soak.

## Verification checklist

- [ ] All Category-B request-path lookups wrapped; `org_id` still read from row.
- [ ] `zitiCtx` + the fresh-background bg jobs wrapped at their root.
- [ ] webauthn login lookups carry `AND org_id = $2`.
- [ ] `findRouteByHost` bypass site has the host-uniqueness comment.
- [ ] Integration test fails on a plain `rlsRolePool` query / passes under bypass.
- [ ] `go build`/`vet`/`gofmt`/`orgscope` green; access+apikeys unit tests green.
- [ ] (post-merge, live) box re-cutover brings up all 8, proxy + api-key + Ziti OK.
