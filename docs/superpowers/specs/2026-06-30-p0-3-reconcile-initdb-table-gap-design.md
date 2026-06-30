# P0-3 — Reconcile the init-db ↔ migrations table gap (v54) + recurrence guard

## Context

OpenIDX has two divergent schema sources:

- `deployments/docker/init-db.sql` — runs once on **docker-compose** Postgres bring-up.
- `internal/migrations/*.go` — the versioned runner used by **every other deploy**
  (managed Postgres / RDS / Helm / `cmd/migrate`).

**58 tables are created only by `init-db.sql` and by no migration.** On a
migrate-based install those tables don't exist, so the code that reads/writes
them 500s. **56 of the 58 are used by app code** (verified by grepping
`internal/` for each table name in a SQL string); 2 (`health_check_history`,
`webhook_delivery_stats`) have zero code references.

Affected feature areas (examples): MFA variants (`mfa_sms`, `mfa_email_otp`,
`mfa_otp_challenges`, `mfa_phone_call`, `phone_call_challenges`, `mfa_bypass_codes`,
`mfa_bypass_audit`, `hardware_tokens`, `biometric_*`), passwordless
(`magic_links`, `passwordless_preferences`), SAML/social/federation
(`saml_service_providers`, `social_providers`, `social_account_links`,
`federation_rules`, `custom_claims_mappings`, `user_identity_links`), lifecycle
(`lifecycle_policies/workflows/executions`, `temp_access_*`), ISPM
(`ispm_findings/rules/scores`), audit/archival (`unified_audit_events`,
`audit_archives`, `audit_retention_policies`, `admin_audit_log`,
`external_audit_sync_state`), bulk-ops, notifications/email
(`email_templates`, `email_branding`, `broadcast_messages`,
`notification_routing_rules`), analytics, developer tools, guacamole, and ziti
fabric (`ziti_edge_routers`, `ziti_metrics`, `ziti_user_sync`).

This is the recurring "init-db ↔ migrations drift": the v38–v45 migrations
already reconciled ~15 such tables in the same way; 58 remain. It has reached
`main` ≥4 times. **This spec both closes the current gap and adds a guard so it
cannot recur.**

The full authoritative list of 58 table names is in the implementation plan.

## Approach

Two parts, both following established repo conventions.

### Part 1 — Migration `v54` `reconcile_initdb_table_gap`

Mirror the v38–v45 reconcile pattern exactly:

- New file `internal/migrations/sql_v54.go` with two package-level string vars
  `reconcileTableGapUp` and `reconcileTableGapDown`, plus a package doc comment
  in the v44 style (what/why/source/idempotency).
- Register it in `internal/migrations/loader.go`'s `allMigrations()` slice as the
  next entry after v53: `{Version: 54, Name: "reconcile_initdb_table_gap",
  Description: …, UpSQL: reconcileTableGapUp, DownSQL: reconcileTableGapDown}`.

**`reconcileTableGapUp`** contains the **verbatim** DDL for all **58** tables,
lifted from `init-db.sql`:

- Each `CREATE TABLE` becomes `CREATE TABLE IF NOT EXISTS` (most already are).
- Preserve `init-db.sql`'s relative ordering of these tables so any inter-table
  foreign keys resolve (init-db.sql is itself a working ordered script). FKs to
  always-present core tables (`users`, `organizations`, `oauth_clients`, …) are
  fine; FKs among the 58 are satisfied by ordering.
- Include each table's **own** associated `CREATE INDEX` / constraint statements
  that immediately follow it in `init-db.sql`, rewritten `CREATE INDEX IF NOT
  EXISTS` for idempotency (matches v44's treatment).
- Include **all 58** (the 2 unused too) — same effort, fully closes the drift,
  and required for the Part 2 guard to stay green.

Idempotent throughout, so v54 is a **no-op on docker-compose** clusters
(everything `IF NOT EXISTS`) and **creates the 58** on migrate-only clusters.

**Not added to the v37 RLS belt** (consistent with v38–v45). This is safe under
the `openidx_app` cutover: RLS only enforces on the 68 tables v37 `FORCE`s, so
these non-belt tables are *not* subject to fail-closed policies and won't repeat
the P0-2 regression. (Whether any of them should later join the belt is a
separate, deliberate decision — out of scope here.)

**`reconcileTableGapDown`**: `DROP TABLE IF EXISTS <name> CASCADE;` for the 58
(mirrors the v38–v45 Downs). Rollback is inherently destructive of those tables'
data; that is the standard reconcile-migration contract.

### Part 2 — Recurrence guard (root-cause fix)

A Go test in `internal/migrations` (e.g. `initdb_parity_test.go`) that:

1. Reads `deployments/docker/init-db.sql` (resolve the path relative to the test
   file via runtime, or a repo-root walk) and extracts its `CREATE TABLE` name
   set with a regex (`CREATE TABLE (IF NOT EXISTS )?<name>`), normalized
   (lowercase, strip schema/quotes).
2. Extracts the `CREATE TABLE` name set from every migration's `UpSQL` (iterate
   `allMigrations()` and regex each `UpSQL`), and the set of names a migration
   `UpSQL` `DROP`s (so intentionally-dropped tables are excluded).
3. Asserts `initdbTables − migrationCreated − migrationDropped == ∅` — i.e. every
   table in `init-db.sql` is created by some migration (or intentionally
   dropped). Fails with the offending names listed.

This makes the drift a **build-time failure**: adding a table to `init-db.sql`
without a migration breaks CI (it runs in the `internal/migrations` unit-test
job, which is part of `Required Checks`). It does **not** assert the reverse
direction (migration-only tables absent from init-db) — that's the low-impact
reverse drift, explicitly out of scope.

## Out of scope (deliberate)

- The 9-table **reverse drift** (migration-only tables not in `init-db.sql`) —
  audit P2; low impact because the migrator also runs on docker installs and is
  additive.
- **Adding any reconciled table to the RLS belt** — separate decision.
- **Collapsing the two schema sources** into one (reduce `init-db.sql` to
  extensions/roles/seed and always run migrations) — the larger root-cause
  refactor. The Part 2 guard is the pragmatic 80% that prevents recurrence
  without that refactor.

## Testing / verification

- The new parity guard test passes (and is proven to fail if a name is removed
  from v54).
- Migration applies on a fresh migrate-only Postgres: all 58 tables exist
  afterward; a second `migrate` run is a clean no-op (idempotent). Verified via
  the existing testcontainer-based migration tests if present, else on the box
  against a throwaway database.
- `go build ./...`, `go vet ./...`, `gofmt`, `go run ./tools/orgscope -fail
  ./internal` (no app SQL added → unchanged), and `go test ./internal/migrations/...`
  all green.
- Spot-check: a previously-500ing endpoint backed by one of the 58 (e.g. an MFA
  or SAML feature) no longer 500s on a migrate-only DB.

## Verification checklist

- [ ] `sql_v54.go` created; all 58 tables, verbatim, `IF NOT EXISTS`, init-db
  ordering preserved; per-table indexes included and idempotent.
- [ ] Registered as Version 54 in `loader.go` with a descriptive entry.
- [ ] `Down` drops the 58 `IF EXISTS`.
- [ ] Parity guard test added; green; fails if v54 omits a table.
- [ ] Migration applies cleanly + idempotently on a fresh DB.
- [ ] build / vet / gofmt / orgscope / migration tests green.
