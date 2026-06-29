# P0-2 — Bypass-wrap pre-resolution lookups: Implementation Plan

> **For agentic workers:** mechanical `orgctx.WithBypassRLS(ctx)` wraps at an
> enumerated set of pre-tenant-resolution lookups + one defense-in-depth
> org-scope on webauthn, plus a regression integration test. Executed inline.

**Goal:** Make every pre-tenant-resolution lookup against a FORCE-RLS table
return rows under the `openidx_app` role, so the box/compose can re-cut-over to
RLS-enforcing without breaking the access proxy, API-key auth, device-trust,
posture, or Ziti startup.

**Architecture:** Wrap the ctx of each enumerated lookup in
`orgctx.WithBypassRLS(...)` (the existing opt-in escape hatch); the query still
reads `org_id` out of the row. WebAuthn login is org-scoped instead (org is
resolved on the subdomain login path). One integration test pins the failure
mode + remedy.

**Tech stack:** Go, pgx v5, `internal/common/orgctx`, integration build tag.

---

## Task 1: api_keys auth (`internal/apikeys/service.go`)

**Files:** Modify `internal/apikeys/service.go:320,461`

- [ ] `ValidateAPIKey` lookup (line 320): change `s.db.Pool.QueryRow(ctx,` →
  `s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),`. (orgctx already imported.)
- [ ] `updateLastUsed` (line 461): change `s.db.Pool.Exec(ctx,` →
  `s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),`.
- [ ] `go build ./internal/apikeys/` green. Commit.

## Task 2: access proxy data plane (`internal/access/service.go`)

**Files:** Modify `internal/access/service.go:2254,1586,1590,2479,232`
(orgctx already imported.)

- [ ] `findRouteByHost` (2254): wrap ctx → `orgctx.WithBypassRLS(ctx)`. Add a
  comment above the call: `// Bypass RLS: route resolution runs before the org
  is known — the host IS what resolves the tenant. Hosts are globally unique
  across tenants (a subdomain maps to exactly one org), so the priority-ordered
  LIMIT 1 stays unambiguous.`
- [ ] `handleLogout` (1586 SELECT, 1590 UPDATE): wrap both
  `c.Request.Context()` → `orgctx.WithBypassRLS(c.Request.Context())`.
- [ ] `updateSessionActivity` (2479): wrap ctx.
- [ ] `deleteAppTile` (232): wrap ctx.
- [ ] `go build ./internal/access/` green. Commit.

## Task 3: forward-auth reads (`device_trust.go`, `context_evaluator.go`)

**Files:** Modify `internal/access/device_trust.go`,
`internal/access/context_evaluator.go` (both NEED the orgctx import added).

- [ ] device_trust.go: add `"github.com/openidx/openidx/internal/common/orgctx"`
  to imports. In `deviceTrusted`, after the `userID==""` guard, add
  `ctx = orgctx.WithBypassRLS(ctx)`. Same in `ensureDeviceTrustRequest` after
  its `userID==""` guard. (Covers the known_devices reads; the
  non-FORCE-RLS `device_trust_requests` queries are unaffected.)
- [ ] context_evaluator.go: add the orgctx import. At the ziti_identities lookup
  (line 80), wrap ctx → `orgctx.WithBypassRLS(ctx)`.
- [ ] `go build ./internal/access/` green. Commit.

## Task 4: Ziti edge + agent callback (`ziti.go`, `agent_api.go`)

**Files:** Modify `internal/access/ziti.go:458`,
`internal/access/agent_api.go:479,740` (both import orgctx already).

- [ ] ziti.go `forwardHTTPConnection` (458): change
  `context.WithTimeout(context.Background(), ...)` →
  `context.WithTimeout(orgctx.WithBypassRLS(context.Background()), ...)`.
- [ ] agent_api.go `bridgeDevicePostureResult` (479): as first statement after
  the `h.db==nil` guard, add `ctx = orgctx.WithBypassRLS(ctx)` (covers the
  ziti_identities read, posture_checks read, and device_posture_results write).
- [ ] agent_api.go `loadIntegrityPolicy` (740): after the `h.db==nil` guard,
  add `ctx = orgctx.WithBypassRLS(ctx)`.
- [ ] `go build ./internal/access/` green. Commit.

## Task 5: shared oauth client + Integrity Doctor + audit sync

**Files:** Modify `internal/access/app_publish.go:464`,
`internal/access/health_handlers.go:619,622,639`,
`internal/access/unified_audit.go:478` (app_publish imports orgctx;
health_handlers + unified_audit NEED the import added).

- [ ] app_publish.go `registerAccessProxyCallback` (464): wrap ctx in the Exec.
- [ ] health_handlers.go: add orgctx import. In `handleHealthRelations`, wrap
  both `c.Request.Context()` (619 ScanAndHeal, 622 Scan) in
  `orgctx.WithBypassRLS(...)`. In `handleHealthFix`, wrap `c.Request.Context()`
  (639 FixOne). (Install-wide admin diagnostic.)
- [ ] unified_audit.go `handleSyncExternalAuditEvents` (478): add orgctx import;
  wrap `c.Request.Context()` in `orgctx.WithBypassRLS(...)`. (The background
  caller via `bgCtx` is already bypassed; this fixes the admin HTTP trigger.)
- [ ] `go build ./internal/access/` green. Commit.

## Task 6: access startup zitiCtx + webhook bookkeeping

**Files:** Modify `cmd/access-service/main.go:303`,
`internal/audit/stream.go:633,653` (both import orgctx already).

- [ ] main.go (303): `zitiCtx, zitiCancel := context.WithCancel(context.Background())`
  → `context.WithCancel(orgctx.WithBypassRLS(context.Background()))`. Fixes the
  imperative-startup cascade (HostAllServices, EnsureZitiServicesForRoutes,
  EnsureBrowZerRouterService, BrowZer config writers).
- [ ] stream.go (633, 653): change `context.WithTimeout(context.Background(), ...)`
  → `context.WithTimeout(orgctx.WithBypassRLS(context.Background()), ...)`.
- [ ] `go build ./...` green. Commit.

## Task 7: webauthn org-scoping (defense-in-depth)

**Files:** Modify `internal/identity/webauthn.go:237,304` (NEEDS orgctx import).

- [ ] Add orgctx import. In `BeginWebAuthnAuthentication`, before the query:
  `org, err := orgctx.From(ctx); if err != nil { return nil, err }`; change the
  query to `… WHERE username = $1 AND org_id = $2 AND enabled = true` and pass
  `username, org.ID`.
- [ ] In `FinishWebAuthnAuthentication`, same: `org, err := orgctx.From(ctx); if
  err != nil { return "", err }`; query `… AND org_id = $2 …`, pass
  `username, org.ID`. (Mirrors `identity/service.go` GetUser pattern.)
- [ ] `go build ./internal/identity/` green. Commit.

## Task 8: regression integration test

**Files:** Modify `test/integration/cross_org_test.go`

- [ ] Add `TestPreResolutionLookupsUnderRLS` (integration build tag). Using the
  existing harness: `seedOrg` org A; under `bypassExec` insert one `api_keys`
  row (org A, a known `key_hash`) and one `proxy_routes` row (org A, a known
  `from_url`).
- [ ] On the NOSUPERUSER `rlsRolePool` connection with **no** `app.org_id` GUC:
  assert `SELECT count(*) FROM api_keys WHERE key_hash=$1` = 0 and
  `SELECT count(*) FROM proxy_routes WHERE from_url LIKE '%'||$1||'%'` = 0
  (the live failure mode).
- [ ] Then `SET app.bypass_rls='on'` on that same connection and assert both
  counts = 1 (the remedy the code now applies). Skip if DB/role absent.
- [ ] `go vet -tags=integration ./test/integration/` clean. Commit.

## Verification

- [ ] `go build ./...`, `go vet ./...`, `gofmt -l` clean,
  `go run ./tools/orgscope -fail ./internal` green (no new org-less SQL).
- [ ] `go test ./internal/access/... ./internal/apikeys/... ./internal/identity/...` green.
- [ ] (post-merge, live) box re-cutover: re-point env to `openidx_app`, restart
  8; `psm.tdv.org`→302, bogus host→404, api-key validates, access log clean
  Ziti startup; `TestRLSBelt` still passes (RLS still enforces scoped reads).
