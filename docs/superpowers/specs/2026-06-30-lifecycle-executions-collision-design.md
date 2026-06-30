# Fix the `lifecycle_executions` schema collision (split out `lifecycle_policy_executions`)

## Context

`deployments/docker/init-db.sql` defines `lifecycle_executions` **twice with
incompatible schemas** — two unrelated features collided on one table name:

- **Workflow runs** (`internal/identity/service.go`) — `lifecycle_workflows` +
  `lifecycle_executions` keyed by `workflow_id`, `user_id`, `triggered_by`,
  `trigger_type`, `actions_completed/failed`, … This is a *per-user* workflow
  execution. Its `CREATE TABLE` comes **first** in init-db.sql, so it **wins**
  (`CREATE TABLE IF NOT EXISTS` → the second is a no-op). Migration **v54** also
  created this schema. This path works.
- **Policy runs** (`internal/admin/deprovisioning.go`) — `lifecycle_policies` +
  `lifecycle_executions` keyed by `policy_id`, `users_scanned`, `users_affected`,
  `actions_taken`, `error_message`. This is a *per-policy* deprovisioning run
  (scan N users, act). Its `CREATE TABLE` is the **second**, dead, definition.

Because the workflow schema wins, the deprovisioning code references columns that
don't exist, so **all three of its `lifecycle_executions` queries fail at runtime
on every install**:

- `deprovisioning.go:329` — `INSERT INTO lifecycle_executions (policy_id, status,
  users_scanned) …`
- `deprovisioning.go:484` — `UPDATE lifecycle_executions SET … users_affected,
  actions_taken, completed_at …`
- `deprovisioning.go:497` — `SELECT id, policy_id, status, users_scanned,
  users_affected, actions_taken, started_at, completed_at, error_message FROM
  lifecycle_executions WHERE policy_id = $1 …`

So "run a deprovisioning policy" creates no usable execution record and listing
runs 500s. (No data to migrate — every prior insert errored.) Surfaced while
building v54 (P0-3); the dead `idx_lifecycle_exec_policy` index was already
omitted from v54 for the same reason.

## Approach

They are distinct concepts that should never have shared a name. Give the policy
path its own table, `lifecycle_policy_executions`, and leave `lifecycle_executions`
as the workflow table.

### 1. `init-db.sql` — rename the dead second definition

Rename the **second** (`policy_id`) `lifecycle_executions` block (init-db.sql
~line 2997) to `CREATE TABLE IF NOT EXISTS lifecycle_policy_executions (…)` with
the same columns, and re-point its index:
`CREATE INDEX IF NOT EXISTS idx_lifecycle_policy_exec ON
lifecycle_policy_executions(policy_id, started_at DESC);`

This removes the duplicate-definition footgun at the source: init-db now has
`lifecycle_executions` (workflow schema, first block, unchanged) **and**
`lifecycle_policy_executions` (policy schema), each correct and distinct, with a
working index.

### 2. New migration `v55` — `lifecycle_policy_executions`

`internal/migrations/sql_v55.go` + `loader.go` entry (Version 55), mirroring the
v54 style:

```sql
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
```

Idempotent; no-op on docker (init-db already made it after step 1). The
`policy_id → lifecycle_policies(id)` FK resolves because `lifecycle_policies`
exists (created by v54) and v55 runs after v54. `Down`: `DROP TABLE IF EXISTS
lifecycle_policy_executions CASCADE;`.

Not added to the v37 RLS belt (consistent with v54 and the other reconciled
tables; non-FORCE → `openidx_app` unaffected).

### 3. `internal/admin/deprovisioning.go` — point the 3 queries at the new table

Change `lifecycle_executions` → `lifecycle_policy_executions` in the INSERT
(:329), UPDATE (:484), and SELECT (:497). No column or logic changes — the
columns now exist on the target table, so the deprovisioning execution log works.

## Why the guard stays green

`TestInitDBParity` requires every `init-db.sql` table to be created by some
migration. After step 1, init-db gains `lifecycle_policy_executions`; step 2's
v55 creates it → guard passes. `lifecycle_executions` remains in init-db (first
block) and is created by v54 → still covered. The guard only checks init-db ⊆
migrations, so no reverse-direction issue.

## Out of scope

- Adding `org_id` / RLS-belt membership to the new table (separate concern;
  matches the other reconciled tables which are not org-scoped).
- Touching the workflow `lifecycle_executions` path (`internal/identity`) — it is
  correct and unchanged.
- Backfilling old policy-run rows (none exist — every prior insert errored).

## Testing / verification

- `go build ./...`, `go vet ./...`, `gofmt`, `go run ./tools/orgscope -fail
  ./internal` (deprovisioning's new queries key on `policy_id`, not org — verify
  orgscope stays green; the prior `lifecycle_executions` queries were already
  accepted, and the table/columns are non-org-scoped, so no new flag).
- `go test ./internal/migrations/...` — `TestAllMigrationsIntegrity` (1..55) and
  `TestInitDBParity` green.
- End-to-end: full `cmd/migrate up` chain v1→v55 applies cleanly + idempotently
  on a fresh DB; `lifecycle_policy_executions` exists with the policy schema and
  `lifecycle_executions` retains the workflow schema.
- Functional spot-check (box / live DB): a deprovisioning policy run now inserts
  an execution row and the list endpoint returns it (previously 500/errored).

## Verification checklist

- [ ] init-db.sql second block renamed to `lifecycle_policy_executions` + index re-pointed.
- [ ] `sql_v55.go` creates `lifecycle_policy_executions` (+ index), registered as v55, Down drops it.
- [ ] deprovisioning.go INSERT/UPDATE/SELECT use `lifecycle_policy_executions`.
- [ ] `TestInitDBParity` + `TestAllMigrationsIntegrity` green; full chain applies + idempotent.
- [ ] build / vet / gofmt / orgscope green.
