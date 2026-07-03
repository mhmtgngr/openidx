# Column-level init-db↔migrations parity guard + drift reconcile (readiness W2.9)

> Third item of Workstream 2. `TestInitDBParity` only checked table **existence**, so
> tables present in both `init-db.sql` and migrations could still have **divergent column
> sets** — invisible drift that breaks **migrate-only installs** (RDS/Helm/`migrate up`,
> which never run `init-db.sql`). This adds a column-level guard and reconciles the drift it
> finds.

## Investigation (done)

Prototyped the column comparison (parse columns from every `CREATE TABLE` block **and** every
`ALTER TABLE … ADD COLUMN` on both sides; for each table in both sources, flag init-db columns
created by no migration). The drift surface is **9 tables**, not the 1 the survey named:

- **`ziti_certificates`** — wholesale schema divergence. The migration schema (`cert_data NOT NULL`,
  `private_key_encrypted`, `ca_chain`, `expires_at`, `identity_id`) is stale; the code
  (`internal/access/ziti_hardening.go`) and init-db use `{cert_type, subject, issuer, serial_number,
  fingerprint, not_before, not_after, auto_renew, renewal_threshold_days, pem_data, status,
  associated_identity_id}`. On a migrate-only install the cert-hardening SELECTs fail on missing
  columns, and `cert_data`'s NOT NULL breaks the code's INSERT (which omits it).
- **8 more** where `init-db.sql` accumulated `ALTER … ADD COLUMN IF NOT EXISTS` patches never
  mirrored to a migration: `application_sso_settings` (8 session-policy cols), `directory_sync_state`
  (`last_delta_link`), `ip_threat_list` (`is_active`), `oauth_clients` (`front/back_channel_logout_uri`),
  `user_roles` (`expiry_notified`), `user_sessions` (`risk_score, auth_methods, device_name,
  device_type, location`), `users` (`external_id`), `ziti_service_policies` (`is_system,
  posture_check_roles`).

(The earlier survey/first prototype under-reported because it didn't parse `ALTER … ADD COLUMN` on
the init-db side; the Go guard parses both sides.)

## Design

**1. `TestInitDBColumnParity`** (`internal/migrations/initdb_parity_test.go`). Parses columns from
`CREATE TABLE` blocks + `ALTER … ADD COLUMN` in both `init-db.sql` and the concatenated migration
`UpSQL`. For every table present in **both**, asserts each init-db column is created by some
migration. **Directional** (init-db ⊆ migrations), matching the existing table-level guard:
migration-only extra columns don't break init-db installs. Table-only-in-init-db is left to the
existing `TestInitDBParity` (no double-reporting). A sanity floor (≥150 parsed `CREATE TABLE`)
guards against a too-strict regex silently passing.

**2. Migration v63 — `column_drift_reconcile`** (`internal/migrations/sql_v63.go`). Reconciles every
flagged column:
- `ziti_certificates`: `ADD COLUMN IF NOT EXISTS` the 12 real columns (FK + `UNIQUE` inline so the
  `IF NOT EXISTS` guard covers them) + the two indexes, then `DROP COLUMN IF EXISTS` the 5 stale ones
  (safe — the NOT NULL break means no rows were ever inserted on migrate-only installs).
- The other 8 tables: `ADD COLUMN IF NOT EXISTS` mirroring init-db's exact definitions.
- All plain, idempotent statements (splitSQL can't handle `DO $$`). **`init-db.sql` is unchanged** —
  it already defines all of these; v63 brings the migration path up to it.
- **Down** reverses only the `ziti_certificates` schema swap; the other ADDs mirror columns init-db
  defines independently, so dropping them would diverge a compose install from its own schema and
  could destroy live data (`users.external_id`) — they're intentionally left.

## Testing
- `go test ./internal/migrations/ -run TestInitDBParity` and `-run TestInitDBColumnParity` green
  (the column test **failed on the 8 tables before v63 was expanded** — proving it has teeth — and
  passes after). `go build ./...`, `go vet`, `gofmt`, `orgscope -fail ./internal` clean.
- Migration applies on top of init-db and on a fresh init-db (CI Integration Tests).

## Out of scope
`org_id`/RLS on `jit_grants`/`request_approval_chains` (W2.10). This item is the column guard +
reconcile only.

## Critical files
- New: `internal/migrations/sql_v63.go`. Edit: `internal/migrations/loader.go` (register v63),
  `internal/migrations/initdb_parity_test.go` (column guard). `init-db.sql` unchanged.
