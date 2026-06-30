# P0-3 — Reconcile init-db ↔ migrations table gap (v54): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Create the 58 `init-db.sql`-only tables in a versioned migration (v54) so migrate-based installs (RDS/Helm/`cmd/migrate`) stop 500ing, and add a guard test so the drift can't recur.

**Architecture:** One idempotent reconcile migration `sql_v54.go` (verbatim DDL lifted from `init-db.sql`, `IF NOT EXISTS`) registered in `loader.go`, plus a pure-string parity test asserting every `init-db.sql` table is created by some migration.

**Tech Stack:** Go, PostgreSQL DDL, `internal/migrations` runner (splitSQL-based), regexp.

---

## The 58 missing tables (authoritative, init-db order is determined at extraction time)

```
admin_audit_log admin_delegations api_usage_metrics attestation_campaigns
attestation_items audit_archives audit_retention_policies biometric_policies
biometric_preferences broadcast_messages bulk_operation_items bulk_operations
campaign_runs connection_tests custom_claims_mappings developer_settings
email_branding email_templates entitlement_metadata error_catalog
external_audit_sync_state feature_adoption federation_rules guacamole_connection_pool
guacamole_connections hardware_token_events hardware_tokens health_check_history
ip_geolocation_cache ispm_findings ispm_rules ispm_scores lifecycle_executions
lifecycle_policies lifecycle_workflows magic_links mfa_bypass_audit mfa_bypass_codes
mfa_email_otp mfa_otp_challenges mfa_phone_call mfa_sms notification_routing_rules
oauth_playground_sessions passwordless_preferences phone_call_challenges
saml_service_providers social_account_links social_providers temp_access_links
temp_access_usage unified_audit_events user_identity_links user_risk_baselines
webhook_delivery_stats ziti_edge_routers ziti_metrics ziti_user_sync
```

(56 used by code, 2 unused — `health_check_history`, `webhook_delivery_stats` — included anyway so the Part-2 guard stays green and the drift is fully closed.)

---

## Task 1: Generate the v54 DDL by extraction (no hand-copy)

**Files:** Create `internal/migrations/sql_v54.go`

Hand-copying 58 tables is error-prone. Extract them verbatim from `init-db.sql` with a one-off script (NOT committed), sanity-check, then embed.

- [ ] **Step 1: Write the extraction script** `/tmp/extract_v54.py`:

```python
import re, sys

NAMES = set("""
admin_audit_log admin_delegations api_usage_metrics attestation_campaigns
attestation_items audit_archives audit_retention_policies biometric_policies
biometric_preferences broadcast_messages bulk_operation_items bulk_operations
campaign_runs connection_tests custom_claims_mappings developer_settings
email_branding email_templates entitlement_metadata error_catalog
external_audit_sync_state feature_adoption federation_rules guacamole_connection_pool
guacamole_connections hardware_token_events hardware_tokens health_check_history
ip_geolocation_cache ispm_findings ispm_rules ispm_scores lifecycle_executions
lifecycle_policies lifecycle_workflows magic_links mfa_bypass_audit mfa_bypass_codes
mfa_email_otp mfa_otp_challenges mfa_phone_call mfa_sms notification_routing_rules
oauth_playground_sessions passwordless_preferences phone_call_challenges
saml_service_providers social_account_links social_providers temp_access_links
temp_access_usage unified_audit_events user_identity_links user_risk_baselines
webhook_delivery_stats ziti_edge_routers ziti_metrics ziti_user_sync
""".split())

sql = open("deployments/docker/init-db.sql").read()

# Statement scanner: split on ';' at paren-depth 0 and NOT inside a $$...$$ block.
stmts, buf, depth, in_dollar = [], "", 0, False
i = 0
while i < len(sql):
    ch = sql[i]
    if sql[i:i+2] == "$$":
        in_dollar = not in_dollar
        buf += "$$"; i += 2; continue
    buf += ch
    if not in_dollar:
        if ch == "(": depth += 1
        elif ch == ")": depth -= 1
        elif ch == ";" and depth == 0:
            stmts.append(buf.strip()); buf = ""
    i += 1
if buf.strip(): stmts.append(buf.strip())

ct = re.compile(r'(?is)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?')
idx_on = re.compile(r'(?is)\bON\s+(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?')
is_idx = re.compile(r'(?is)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX')

out, table_count = [], 0
for s in stmts:
    m = ct.match(s)
    if m and m.group(1).lower() in NAMES:
        s = re.sub(r'(?is)^(\s*CREATE\s+TABLE\s+)(?!IF\s+NOT\s+EXISTS)', r'\1IF NOT EXISTS ', s, count=1)
        out.append(s + ";"); table_count += 1; continue
    if is_idx.match(s):
        mo = idx_on.search(s)
        if mo and mo.group(1).lower() in NAMES:
            s = re.sub(r'(?is)^(\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+)(?!IF\s+NOT\s+EXISTS)', r'\1IF NOT EXISTS ', s, count=1)
            out.append(s + ";")

body = "\n\n".join(out)
sys.stderr.write(f"CREATE TABLE extracted: {table_count} (expect 58)\n")
sys.stderr.write(f"backtick present: {'`' in body}\n")
found = {ct.match(s).group(1).lower() for s in out if ct.match(s)}
missing = sorted(NAMES - found)
sys.stderr.write(f"names not extracted: {missing}\n")
print(body)
```

- [ ] **Step 2: Run it and sanity-check**

Run: `cd /home/cmit/openidx && python3 /tmp/extract_v54.py > /tmp/v54_body.sql 2>/tmp/v54_stat.txt; cat /tmp/v54_stat.txt`

Expected: `CREATE TABLE extracted: 58`, `backtick present: False`, `names not extracted: []`.
- If count ≠ 58 or names remain: a table's DDL didn't match (e.g. odd whitespace) — inspect that table's block in `init-db.sql` and adjust the regex; do NOT proceed with a partial set.
- If `backtick present: True`: the Go raw-string literal can't hold it — wrap the offending value, or switch that one statement to a separate double-quoted Go string concatenation. (Postgres DDL normally has none.)

- [ ] **Step 3: Verify the extracted SQL parses** (catch truncated blocks)

Run (throwaway DB, idempotency + validity in one shot):
```bash
docker exec -i oidx-pg psql -U openidx -d postgres -c "DROP DATABASE IF EXISTS v54_probe;" -c "CREATE DATABASE v54_probe;"
docker exec -i oidx-pg psql -U openidx -d v54_probe -v ON_ERROR_STOP=1 -f - < /tmp/v54_body.sql && echo "APPLY OK"
# idempotency: re-apply must also succeed (all IF NOT EXISTS)
docker exec -i oidx-pg psql -U openidx -d v54_probe -v ON_ERROR_STOP=1 -f - < /tmp/v54_body.sql && echo "REAPPLY OK"
docker exec -i oidx-pg psql -U openidx -d v54_probe -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
```
Expected: `APPLY OK`, `REAPPLY OK`. The count is ≥58 (some of the 58 FK core tables that init-db creates earlier may be absent in this probe DB — if APPLY fails on a missing FK target, that target is a non-58 init-db table; for the probe only, prepend those parent `CREATE TABLE`s or drop the FK check by testing against a DB that already has the core schema. The REAL validity test is Task 4 against a fully-migrated DB. If APPLY fails ONLY on FK-target-missing, that is expected in the bare probe and Task 4 is authoritative.)

- [ ] **Step 4: Assemble `internal/migrations/sql_v54.go`**

```go
package migrations

// Migration v54 — reconcile the remaining init-db.sql-only tables into the
// versioned migration set (the broad pass after v38–v45 covered ~15).
//
// 58 tables existed only in deployments/docker/init-db.sql, so managed-Postgres /
// RDS / Helm / `migrate` installs (which never run init-db.sql) lacked them and
// 500'd across MFA variants, SAML/social/federation, lifecycle, ISPM, audit
// archival, bulk-ops, biometric, passwordless, guacamole and ziti-fabric
// features. DDL is lifted verbatim from init-db.sql, made CREATE TABLE/INDEX IF
// NOT EXISTS, so this is a no-op on docker-compose installs and creates the gap
// elsewhere. Not placed under the v37 RLS belt (consistent with v38–v45); these
// are non-FORCE tables so the openidx_app role is unaffected.
var reconcileTableGapUp = `-- Migration 054: reconcile the 58 init-db.sql-only tables.
<PASTE /tmp/v54_body.sql HERE VERBATIM>
`

var reconcileTableGapDown = `-- Migration 054 down: drop the reconciled tables.
<DROP TABLE IF EXISTS <name> CASCADE; for each of the 58, reverse dependency order>
`
```

Generate the Down list:
```bash
python3 - <<'PY'
names="""<the 58 names>""".split()
print("\n".join(f"DROP TABLE IF EXISTS {n} CASCADE;" for n in names))
PY
```
(`CASCADE` so FKs among the 58 don't block the drop; order then doesn't matter.)

- [ ] **Step 5: `gofmt` + build**

Run: `gofmt -w internal/migrations/sql_v54.go && go build ./internal/migrations/`
Expected: success. (A backtick in the body breaks the build → handle per Step 2.)

- [ ] **Step 6: Commit**
```bash
git add internal/migrations/sql_v54.go
git commit -m "feat(migrations): v54 reconcile_initdb_table_gap — create 58 init-db-only tables"
```

## Task 2: Register v54 in the loader

**Files:** Modify `internal/migrations/loader.go`

- [ ] **Step 1: Add the registry entry** after the v53 block (before the closing `}` of the slice, ~line 385):

```go
		{
			Version:     54,
			Name:        "reconcile_initdb_table_gap",
			Description: "Create the 58 tables that existed only in deployments/docker/init-db.sql so managed-Postgres/RDS/Helm/migrate installs stop 500ing across MFA variants, SAML/social/federation, lifecycle, ISPM, audit archival, bulk-ops, biometric, passwordless, guacamole and ziti-fabric features (the broad init-db<->migrations reconcile after v38–v45's ~15). Verbatim DDL, idempotent (IF NOT EXISTS) so it is a no-op on docker-compose installs. Not under the v37 RLS belt (non-FORCE tables; openidx_app unaffected). A new parity test (TestInitDBParity) keeps this gap from recurring.",
			UpSQL:       reconcileTableGapUp,
			DownSQL:     reconcileTableGapDown,
		},
```

- [ ] **Step 2: Build + integrity test**

Run: `go test ./internal/migrations/ -run TestAllMigrationsIntegrity -v`
Expected: PASS (contiguous 1..54, no dup, non-empty Up/Down). If it reports a gap/empty, fix the entry.

- [ ] **Step 3: Commit**
```bash
git add internal/migrations/loader.go
git commit -m "feat(migrations): register v54 reconcile_initdb_table_gap"
```

## Task 3: Recurrence guard test (TDD — write it, watch it pass, then prove it fails on removal)

**Files:** Create `internal/migrations/initdb_parity_test.go`

- [ ] **Step 1: Write the test**

```go
package migrations

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var createTableRe = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?`)
var dropTableRe = regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?`)

func tableNameSet(re *regexp.Regexp, sql string) map[string]bool {
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(sql, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

// TestInitDBParity guards the recurring init-db<->migrations drift (P0-3): every
// table created by deployments/docker/init-db.sql must also be created by some
// versioned migration (or intentionally dropped by one). A table added to
// init-db.sql without a migration would 500 on managed/RDS/Helm/migrate installs;
// this makes that a CI failure instead of a post-deploy 500.
func TestInitDBParity(t *testing.T) {
	// Go runs tests with CWD = package dir (internal/migrations).
	data, err := os.ReadFile("../../deployments/docker/init-db.sql")
	if err != nil {
		t.Fatalf("read init-db.sql: %v", err)
	}
	initdb := tableNameSet(createTableRe, string(data))
	if len(initdb) < 150 {
		t.Fatalf("parsed only %d CREATE TABLE from init-db.sql; regex too strict?", len(initdb))
	}

	created, dropped := map[string]bool{}, map[string]bool{}
	for _, m := range allMigrations() {
		for n := range tableNameSet(createTableRe, m.UpSQL) {
			created[n] = true
		}
		for n := range tableNameSet(dropTableRe, m.UpSQL) {
			dropped[n] = true
		}
	}

	var missing []string
	for name := range initdb {
		if !created[name] && !dropped[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d table(s) in init-db.sql are created by NO migration "+
			"(init-db<->migrations drift — add them to a reconcile migration):\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
}
```

- [ ] **Step 2: Run it — must PASS now (v54 closes the gap)**

Run: `go test ./internal/migrations/ -run TestInitDBParity -v`
Expected: PASS. If it lists missing tables, Task 1's extraction dropped them → fix v54 (re-run extraction, confirm count 58) before continuing.

- [ ] **Step 3: Prove the guard actually bites** (temporary edit, do NOT commit)

Temporarily delete one `CREATE TABLE IF NOT EXISTS mfa_sms …` line from `sql_v54.go`, run the test, confirm it FAILS naming `mfa_sms`, then restore the line and confirm PASS again.

Run: `go test ./internal/migrations/ -run TestInitDBParity` (after restore) → PASS.

- [ ] **Step 4: Commit**
```bash
git add internal/migrations/initdb_parity_test.go
git commit -m "test(migrations): TestInitDBParity guards init-db<->migrations drift (P0-3)"
```

## Task 4: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build / vet / fmt / orgscope**
```bash
go build ./... && go vet ./internal/migrations/...
gofmt -l internal/migrations/sql_v54.go internal/migrations/loader.go internal/migrations/initdb_parity_test.go
go run ./tools/orgscope -fail ./internal
```
Expected: clean (orgscope unchanged — no app SQL added).

- [ ] **Step 2: Migration package tests**
```bash
go test ./internal/migrations/...
```
Expected: ok (TestAllMigrationsIntegrity + TestInitDBParity + existing).

- [ ] **Step 3: End-to-end apply on a fully-migrated throwaway DB** (authoritative validity)
```bash
# Build the migrate tool and run the whole chain v1..v54 on a fresh DB.
docker exec -i oidx-pg psql -U openidx -d postgres -c "DROP DATABASE IF EXISTS v54_e2e;" -c "CREATE DATABASE v54_e2e;"
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/v54_e2e?sslmode=disable" go run ./cmd/migrate up   # or the repo's migrate entrypoint/flags
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/v54_e2e?sslmode=disable" go run ./cmd/migrate up   # idempotent re-run
docker exec -i oidx-pg psql -U openidx -d v54_e2e -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('mfa_sms','saml_service_providers','lifecycle_policies','unified_audit_events','ziti_edge_routers');"
docker exec -i oidx-pg psql -U openidx -d postgres -c "DROP DATABASE IF EXISTS v54_e2e;"
```
Expected: full chain applies clean, second run is a no-op, the spot-check count = 5 (all present). (Check `cmd/migrate`'s actual invocation/flags first; adapt the command. If `cmd/migrate` isn't the entrypoint, use the repo's documented migrate runner.)

## Self-review notes

- **Spec coverage:** Part 1 → Tasks 1–2; Part 2 guard → Task 3; verification → Task 4.
- **Idempotency:** every statement `IF NOT EXISTS`; Down `IF EXISTS … CASCADE`.
- **Ordering/FK:** extraction preserves init-db.sql order; v54 runs after v1–v53 so all FK targets (core + earlier-migrated tables) exist (Task 4 proves it on the full chain).
- **Type/name consistency:** `reconcileTableGapUp/Down` used in both `sql_v54.go` and the `loader.go` entry; guard regex capture group is the table name.
- **No placeholders** except the explicit `<PASTE …>` / `<DROP …>` markers in Task 1, which are filled by the extraction output in the same task.
