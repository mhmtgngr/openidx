# org_id + RLS belt for jit_grants & request_approval_chains (readiness W2.10)

> Final Workstream 2 item — **defense-in-depth**. v58 (M2a) created `jit_grants` and
> `request_approval_chains` without `org_id`/RLS, reasoning they're org-scoped implicitly
> (jit_grants via its user/role FKs; request_approval_chains via its RLS-scoped
> `access_requests` parent). That holds today, but the v37 FORCE-RLS belt is cheap
> insurance against a future query forgetting the join/filter — the same belt every other
> tenant table carries.

## Status: latent defense-in-depth (these code paths are currently dead)

An adversarial review found that the `JITService` / `RequestService` types that read/write these
tables are **not wired into the running governance-service**: the live `POST /api/v1/governance/requests`
handler is `Service.handleCreateAccessRequest` (`workflows.go`) → `createApprovalRows`, which writes
`access_request_approvals` (not `request_approval_chains`); and the live expiry worker
(`Service.StartJITExpirationChecker`, `jit_expiry.go`) sweeps `access_requests`/`user_roles`/
`group_memberships` (not `jit_grants`). So **no live path reads or writes either table today** — the
belt is inert defense-in-depth for if/when `JITService`/`RequestService` are wired up. That is an
acceptable outcome for this item (the plan scoped W2.10 as low-priority defense-in-depth), and it
also means the belt cannot break anything at runtime.

## Feasibility (were the code paths live)

A FORCE-RLS belt would break a **cross-org background sweep** unless it runs under
`orgctx.WithBypassRLS` (unset `app.org_id` → policy matches nothing → 0 rows). All sweeps that would
scan these tables already bypass, so the belt would be safe even once they are wired:
- `jit.go` `StartExpiryChecker` → `ctx = orgctx.WithBypassRLS(ctx)` (jit.go:321)
- `jit_expiry.go` worker → `WithBypassRLS` (jit_expiry.go:18)
- `request.go` `checkEscalations` → `WithBypassRLS` (request.go:409)

Request-context handlers run with `app.org_id` set (governance-service pool + tenant resolver), so
the belt enforces reads and `WITH CHECK` enforces writes.

## Fix

### Migration v64 — `jit_approval_org_rls`
For both tables: `ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE`
(idempotent, FK inline); backfill from the natural parent (`jit_grants.org_id ← users.org_id` via
`user_id`; `request_approval_chains.org_id ← access_requests.org_id` via `request_id`), oldest-org
fallback so `SET NOT NULL` can't fail; `SET NOT NULL`; index on `org_id`; the v37 belt (USING +
WITH CHECK, ENABLE + FORCE); plain `GRANT` to `openidx_app`. Down disables + drops. Mirrored into
`init-db.sql`.

### Handlers
- `jit.go` `RequestElevation` INSERT → add `org_id = org.ID` (org already resolved via `orgctx.From`).
- `request.go` `SubmitRequest` `request_approval_chains` INSERT → add `org_id = org.ID`.
The cross-org sweeps' UPDATEs/DELETEs run under bypass, unchanged.

## Testing
- `TestRLSBeltJITAndApprovalChains` (integration): seeds org-B FK parents (user, role, access_request)
  + a `jit_grant` and an `approval_chain` under bypass, then asserts an org-A-scoped NOSUPERUSER
  session sees **zero** of org B's rows in both tables and `bypass` sees them. (They can't ride the
  generic `TestRLSBeltTables` loop because of the FK parents.)
- `TestInitDBParity` / `TestInitDBColumnParity` stay green (both tables' `org_id` now in migration +
  init-db). `go build`, `go vet` (incl. `-tags=integration`), `gofmt`, `orgscope -fail ./internal`,
  unit tests — green.

## Out of scope
Workstream 3 hardening (idle-timeout verify, OPA `ValidateProduction`, `VAULT_KEK`). This completes
Workstream 2.

## Critical files
- New: `internal/migrations/sql_v64.go`; edit `loader.go`, `deployments/docker/init-db.sql`,
  `internal/governance/jit.go`, `internal/governance/request.go`,
  `test/integration/cross_org_test.go`. Reuse anchor: the W2.7 attestation belt (v61).
