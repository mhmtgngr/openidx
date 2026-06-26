# Delete the dead ZTPolicy subsystem (governance slice G2) — design

## Context

"G2: register or delete the unused `ZTPolicyHandler` / `zt_policies`." Exploration settled the question decisively toward **delete**:

- **Never wired.** `cmd/governance-service/main.go` registers only `governance.RegisterRoutes` (the `Service` routes). `ZTPolicyHandler.RegisterRoutes` and `NewZTPolicyStore` are constructed *only* in their own test files.
- **No table.** `zt_policies` / `zt_policy_versions` appear in no migration and not in `deployments/docker/init-db.sql`. `ZTPolicyStore` would lazily `CREATE TABLE IF NOT EXISTS` them on first use, but since it's never constructed outside tests, the live DB has no such tables (`SELECT to_regclass('public.zt_policies')` → NULL).
- **No frontend, no cross-references.** Nothing under `web/admin-console/src` references it; nothing outside `internal/governance/zt_policy*.go` references `ZTPolicy`, `ZTPolicyEvaluator`, `ConditionGroup`, `ZTPolicyInput/Result`, or the `Op*`/`Effect*` constants. No other package imports `governance.ZTPolicy` (etc.).
- **Its niche is already filled.** `ZTPolicy` is a general ABAC engine (boolean AND/OR condition trees, versioning, `tenant_id`). Governance already ships **`abac-policies`** — registered handlers, a live `abac_policies` table, and a full admin-console page at `/abac-policies`. After G1, the per-type `policies/policy_rules` engine is the one the access-proxy actually calls. `ZTPolicy` is a third, redundant, unconnected surface.
- **It's a trap.** ~4,866 LOC (3 impl + 3 test files) including a polished-looking `EvaluatePolicies` handler and `PolicyMiddleware` that are unreachable — future readers will reasonably assume it's live.

Build-safety was verified: the `Effect` / `Operator` / `Condition` identifiers that appear elsewhere are unrelated struct field names (e.g. `service.go:2420` `Operator string`) and other packages' own SCIM types — not the ZT types. Deleting the ZT files does not break the build.

## Design

Pure dead-code removal. No behavior change to any live policy surface (`policies/policy_rules` and `abac-policies` are untouched).

### 1. Preserve the shared test harness (do this first)

`setupTestDB(t) (*database.PostgresDB, func())` — the testcontainers Postgres harness — currently lives in `internal/governance/zt_policy_store_test.go`. The G1 round-trip test `TestPolicyRulesRoundTrip` (`policy_rules_roundtrip_test.go`) and the ZT store/handler tests all use it. Deleting `zt_policy_store_test.go` would remove the harness and break the G1 test.

**Move `setupTestDB` verbatim into a new `internal/governance/testdb_test.go`** (package `governance`, same imports: `context`, `testing`, `time`, `testcontainers-go`, `wait`, `zaptest`, `database`) before deleting any ZT file. This is the only code that survives from the deleted set.

### 2. Delete the six ZT files

- `internal/governance/zt_policy.go`
- `internal/governance/zt_policy_handler.go`
- `internal/governance/zt_policy_store.go`
- `internal/governance/zt_policy_test.go`
- `internal/governance/zt_policy_handler_test.go`
- `internal/governance/zt_policy_store_test.go`

No change to `main.go` (it never referenced them) or `init-db.sql` (never had the tables).

### 3. Belt migration v51 — drop the tables if present

`internal/migrations/sql_v51.go` + registration in `internal/migrations/loader.go` after v50.

- **UpSQL:** `DROP TABLE IF EXISTS zt_policy_versions; DROP TABLE IF EXISTS zt_policies;` (versions first — it has a FK to `zt_policies ON DELETE CASCADE`, and dropping the parent first would also work via CASCADE, but explicit child-first is clearest). Idempotent; a no-op on every real install (the tables don't exist), a cleanup on any env where the store was ever constructed (e.g. a stray test against a shared DB).
- **DownSQL:** recreate both tables with the exact DDL `ZTPolicyStore.ensureSchema` used (copied from `zt_policy_store.go` before deletion: `zt_policies`, `zt_policy_versions`, and the four `idx_zt_policies_*` indexes). Strict reversibility even though nothing consumes the tables.
- Follow the existing `sql_vNN.go` pattern: two package-level string vars (`ztPolicyDropUp`, `ztPolicyDropDown`) with a leading `-- Migration 051:` comment, registered as `{Version: 51, Name: "drop_zt_policies", Description: "...", UpSQL: ..., DownSQL: ...}`.

## Out of scope

- The `policies/policy_rules` per-type engine (G1) and the `abac-policies` ABAC engine — both stay exactly as they are.
- Any consolidation of the remaining two policy surfaces (a separate epic if ever desired).
- Devices D2/D3.

## Verification checklist

- `go build ./...`, `go vet ./internal/governance/... ./internal/migrations/...` clean; `gofmt`.
- `go test ./internal/governance/` green — specifically `TestPolicyRulesRoundTrip` still compiles and passes (proves the `setupTestDB` relocation worked), and the suite no longer references any ZT type.
- `go test ./internal/migrations/` green (v51 registers and parses).
- `grep -rn 'ZTPolicy\|zt_policies\|ConditionGroup' internal/ cmd/ --include='*.go'` returns nothing.
- On the box: rebuild + restart `oidx-governance` (binary parity; no behavior change) and apply v51 manually (AUTO_MIGRATE is off) — confirm the `DROP ... IF EXISTS` runs cleanly as a no-op (`to_regclass('public.zt_policies')` stays NULL).
