# Fix `lifecycle_executions` collision — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Split the deprovisioning policy-run log out of the workflow `lifecycle_executions` table into its own `lifecycle_policy_executions`, fixing the broken deprovisioning queries on every install.

**Architecture:** Rename init-db's dead duplicate `lifecycle_executions` (policy schema) → `lifecycle_policy_executions`; add migration v55 to create it on migrate installs; repoint deprovisioning.go's 3 queries. The workflow `lifecycle_executions` (identity path) is untouched. `TestInitDBParity` stays green.

**Tech Stack:** Go, PostgreSQL DDL, `internal/migrations` runner.

---

## Task 1: Rename the dead duplicate in init-db.sql

**Files:** Modify `deployments/docker/init-db.sql` (second `lifecycle_executions` block, ~line 2997, and its index ~line 3009)

- [ ] **Step 1: Rename the second CREATE TABLE**

Replace (the SECOND occurrence — the one with `policy_id`):
```sql
CREATE TABLE IF NOT EXISTS lifecycle_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES lifecycle_policies(id) ON DELETE CASCADE,
```
with:
```sql
CREATE TABLE IF NOT EXISTS lifecycle_policy_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES lifecycle_policies(id) ON DELETE CASCADE,
```
(Edit is uniquely anchored by the `policy_id … REFERENCES lifecycle_policies` line on the next line, which the first/workflow block does not have.)

- [ ] **Step 2: Re-point that block's index**

Replace:
```sql
CREATE INDEX IF NOT EXISTS idx_lifecycle_exec_policy ON lifecycle_executions(policy_id, started_at DESC);
```
with:
```sql
CREATE INDEX IF NOT EXISTS idx_lifecycle_policy_exec ON lifecycle_policy_executions(policy_id, started_at DESC);
```

- [ ] **Step 3: Verify init-db now has both tables, no duplicate**

Run:
```bash
grep -nE "CREATE TABLE IF NOT EXISTS lifecycle_executions \(|CREATE TABLE IF NOT EXISTS lifecycle_policy_executions \(" deployments/docker/init-db.sql
grep -nE "idx_lifecycle_exec_policy|idx_lifecycle_policy_exec" deployments/docker/init-db.sql
```
Expected: exactly ONE `lifecycle_executions (` (the workflow block), ONE `lifecycle_policy_executions (`, and the index is now `idx_lifecycle_policy_exec ON lifecycle_policy_executions`. No remaining `idx_lifecycle_exec_policy`.

## Task 2: Migration v55 creates `lifecycle_policy_executions`

**Files:** Create `internal/migrations/sql_v55.go`; modify `internal/migrations/loader.go`

- [ ] **Step 1: Create `internal/migrations/sql_v55.go`**

```go
package migrations

// Migration v55 — split the deprovisioning policy-run log into its own table.
//
// init-db.sql historically defined lifecycle_executions twice with incompatible
// schemas: a workflow form (workflow_id/user_id, used by internal/identity, which
// wins and is created by v54) and a policy form (policy_id/users_scanned, used by
// internal/admin/deprovisioning). The policy form lost, so deprovisioning's
// INSERT/UPDATE/SELECT referenced non-existent columns and failed on every
// install. This creates the policy-run table under its own name; init-db.sql is
// updated in lockstep (the second block renamed) and deprovisioning.go is
// repointed here. Idempotent; not under the v37 RLS belt (non-FORCE table). FK to
// lifecycle_policies(id) resolves — v54 created lifecycle_policies and v55 runs
// after it.
var lifecyclePolicyExecUp = `-- Migration 055: lifecycle_policy_executions (deprovisioning policy-run log).
CREATE TABLE IF NOT EXISTS lifecycle_policy_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES lifecycle_policies(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'running',
    users_scanned INTEGER DEFAULT 0,
    users_affected INTEGER DEFAULT 0,
    actions_taken JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_policy_exec ON lifecycle_policy_executions(policy_id, started_at DESC);
`

var lifecyclePolicyExecDown = `-- Migration 055 down.
DROP TABLE IF EXISTS lifecycle_policy_executions CASCADE;
`
```

- [ ] **Step 2: Register v55 in `loader.go`** (after the v54 entry, before the slice's closing `}`):

```go
		{
			Version:     55,
			Name:        "lifecycle_policy_executions",
			Description: "Split the deprovisioning policy-run execution log out of the workflow lifecycle_executions table (a name collision: the workflow schema won, so deprovisioning's policy_id queries failed on every install). Creates lifecycle_policy_executions; init-db.sql's dead second block is renamed in lockstep and internal/admin/deprovisioning.go repointed. Idempotent; not under the v37 RLS belt.",
			UpSQL:       lifecyclePolicyExecUp,
			DownSQL:     lifecyclePolicyExecDown,
		},
```

- [ ] **Step 3: Build + integrity test**

Run: `go build ./internal/migrations/ && go test ./internal/migrations/ -run TestAllMigrationsIntegrity -v`
Expected: PASS (contiguous 1..55).

## Task 3: Repoint deprovisioning.go to the new table

**Files:** Modify `internal/admin/deprovisioning.go` (lines 329, 484, 497 — the only 3 `lifecycle_executions` refs, all the policy path)

- [ ] **Step 1: Replace all 3 occurrences**

`lifecycle_executions` → `lifecycle_policy_executions` in:
- `:329` `INSERT INTO lifecycle_executions (policy_id, status, users_scanned) …`
- `:484` `UPDATE lifecycle_executions SET status = 'completed', users_affected = $1, …`
- `:497` `FROM lifecycle_executions WHERE policy_id = $1 …`

(All three are in `internal/admin/deprovisioning.go` and are the only matches there, so a file-scoped replace-all of `lifecycle_executions` → `lifecycle_policy_executions` is correct. Confirm no other match exists first: `grep -c lifecycle_executions internal/admin/deprovisioning.go` must be 3 before, 0 after.)

- [ ] **Step 2: Build + verify no stray refs**

Run:
```bash
go build ./internal/admin/ && go vet ./internal/admin/
grep -n "lifecycle_executions" internal/admin/deprovisioning.go || echo "no workflow-table refs remain (correct)"
grep -c "lifecycle_policy_executions" internal/admin/deprovisioning.go   # expect 3
```
Expected: build OK; the grep finds 0 `lifecycle_executions` and 3 `lifecycle_policy_executions`.

## Task 4: Full verification

**Files:** none

- [ ] **Step 1: Build / vet / fmt / orgscope**
```bash
go build ./... && go vet ./internal/migrations/... ./internal/admin/...
gofmt -l internal/migrations/sql_v55.go internal/migrations/loader.go internal/admin/deprovisioning.go
go run ./tools/orgscope -fail ./internal
```
Expected: clean. (deprovisioning's queries key on `policy_id`, non-org-scoped, same as before — orgscope unchanged.)

- [ ] **Step 2: Migration tests (parity + integrity)**
```bash
go test ./internal/migrations/...
```
Expected: ok — `TestInitDBParity` green (init-db's new `lifecycle_policy_executions` is created by v55; `lifecycle_executions` still by v54) and `TestAllMigrationsIntegrity` (1..55).

- [ ] **Step 3: End-to-end chain on a fresh DB**
```bash
docker exec oidx-pg bash -c 'PGPASSWORD=devpassword psql -U openidx -d postgres -c "DROP DATABASE IF EXISTS lpe_e2e;" -c "CREATE DATABASE lpe_e2e;"'
URL="postgres://openidx:devpassword@localhost:55432/lpe_e2e?sslmode=disable"
DATABASE_URL="$URL" go run ./cmd/migrate up      # full v1..v55
DATABASE_URL="$URL" go run ./cmd/migrate up      # idempotent no-op
# both tables exist with the right distinct schemas:
docker exec oidx-pg bash -c 'PGPASSWORD=devpassword psql -U openidx -d lpe_e2e -tAc "SELECT string_agg(column_name, '"'"','"'"' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name='"'"'lifecycle_policy_executions'"'"';"'
docker exec oidx-pg bash -c 'PGPASSWORD=devpassword psql -U openidx -d lpe_e2e -tAc "SELECT string_agg(column_name, '"'"','"'"' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name='"'"'lifecycle_executions'"'"';"'
# simulate the deprovisioning insert path against the new table (needs a lifecycle_policies row for the FK):
docker exec oidx-pg bash -c 'PGPASSWORD=devpassword psql -U openidx -d lpe_e2e -v ON_ERROR_STOP=1 -c "INSERT INTO lifecycle_policies (id, name) VALUES (gen_random_uuid(), '"'"'probe'"'"') RETURNING id" -c "INSERT INTO lifecycle_policy_executions (policy_id, status, users_scanned) SELECT id, '"'"'running'"'"', 3 FROM lifecycle_policies LIMIT 1 RETURNING id" ' && echo "DEPROVISIONING INSERT PATH OK"
docker exec oidx-pg bash -c 'PGPASSWORD=devpassword psql -U openidx -d postgres -c "DROP DATABASE IF EXISTS lpe_e2e;"'
```
Expected: full chain applies + idempotent; `lifecycle_policy_executions` has the policy schema (`policy_id,…,error_message`), `lifecycle_executions` has the workflow schema (`workflow_id,user_id,…`); the simulated deprovisioning insert succeeds (the bug is fixed). NOTE: `lifecycle_policies`' exact required columns may differ — if the probe INSERT fails on a NOT NULL, add the needed column(s); the load-bearing assertion is that `lifecycle_policy_executions` accepts the `(policy_id, status, users_scanned)` insert.

## Self-review notes
- **Spec coverage:** init-db rename → Task 1; v55 → Task 2; deprovisioning repoint → Task 3; verification → Task 4.
- **Lockstep:** init-db (Task 1) and v55 (Task 2) both produce `lifecycle_policy_executions` so `TestInitDBParity` is satisfied; do not commit Task 2 without Task 1.
- **Name consistency:** table `lifecycle_policy_executions`, index `idx_lifecycle_policy_exec`, vars `lifecyclePolicyExecUp/Down` — used identically across sql_v55.go and loader.go.
- **No data migration** (prior policy-run inserts all errored). Workflow path untouched.
