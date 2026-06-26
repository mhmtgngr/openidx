# Delete the dead ZTPolicy subsystem (G2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the unused `ZTPolicy` subsystem (handler, store, model, tests) from `internal/governance`, preserving the shared `setupTestDB` harness the G1 test depends on, and add a belt migration that drops the never-created `zt_policies`/`zt_policy_versions` tables.

**Architecture:** Pure dead-code removal. `ZTPolicyHandler`/`NewZTPolicyStore` are constructed only in their own tests; the tables exist in no migration and on no live install; nothing under `web/admin-console` or outside `zt_policy*.go` references the ZT types. The only survivor is the `setupTestDB` testcontainers helper (shared with G1's `TestPolicyRulesRoundTrip`), which moves to a new neutral file *before* the deletion. A belt migration `v51` drops the tables `IF EXISTS` (no-op on real installs) with a reversible `Down` that recreates the exact DDL.

**Tech Stack:** Go 1.22, pgx, testcontainers-go, the in-repo migration framework (`internal/migrations/sql_vNN.go` + `loader.go`).

---

### Task 1: Relocate `setupTestDB`, then delete its old home

`setupTestDB` currently lives in `zt_policy_store_test.go`. The G1 test `internal/governance/policy_rules_roundtrip_test.go` (`TestPolicyRulesRoundTrip`) and the remaining ZT handler/model tests call it. We move it to a neutral file `testdb_test.go` and delete `zt_policy_store_test.go` in the **same** task — deleting a test file never breaks the build (the `ZTPolicyStore` impl it tested is still present until Task 3), and doing both here avoids a duplicate-symbol state (two `setupTestDB`) or fragile import surgery.

**Files:**
- Create: `internal/governance/testdb_test.go`
- Delete: `internal/governance/zt_policy_store_test.go` (the function is moved out first; the rest of the file is store-impl tests that Task 3's deletion makes redundant anyway)

- [ ] **Step 1: Create `testdb_test.go` with the relocated helper**

Create `internal/governance/testdb_test.go` with exactly this content (the function is moved verbatim from `zt_policy_store_test.go`; only the file/package comment is new):

```go
// Package governance test helpers shared across the governance test suite.
package governance

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
)

// setupTestDB creates a test database container
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()

	ctx := context.Background()

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Failed to start test container: %v", err)
		return nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}
```

- [ ] **Step 2: Delete the old home of `setupTestDB`**

```bash
cd /home/cmit/openidx
git rm internal/governance/zt_policy_store_test.go
```

This removes the now-duplicate `setupTestDB` (and the `ZTPolicyStore` impl tests, which Task 3 retires anyway). The `ZTPolicyStore` implementation in `zt_policy_store.go` is still present and still compiles; only its tests are gone.

- [ ] **Step 3: Verify the package still builds and the G1 test still finds the relocated harness**

Run: `cd /home/cmit/openidx && gofmt -w internal/governance/testdb_test.go && go vet ./internal/governance/...`
Expected: no output (clean).

Run: `go test ./internal/governance/ -run 'TestPolicyRulesRoundTrip' -count=1 2>&1 | tail -3`
Expected: `--- PASS: TestPolicyRulesRoundTrip` and `ok  github.com/openidx/openidx/internal/governance`.

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/governance/testdb_test.go
git rm --cached internal/governance/zt_policy_store_test.go 2>/dev/null; true
git commit -m "test(governance): relocate setupTestDB to a neutral test file (G2 prep)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

(`git rm` in Step 2 already staged the deletion; the `git add` stages the new file. Both land in one commit.)

---

### Task 2: Add belt migration v51 (drop zt_policies if present)

**Files:**
- Create: `internal/migrations/sql_v51.go`
- Modify: `internal/migrations/loader.go` (append a registration after the v50 entry at lines 358-364)

- [ ] **Step 1: Create the migration SQL file**

Create `internal/migrations/sql_v51.go`:

```go
package migrations

// Migration v51 — drop the dead ZTPolicy tables.
//
// The ZTPolicy subsystem (handler/store/model) was never wired into any
// service: NewZTPolicyStore was constructed only in tests, so its lazy
// CREATE TABLE never ran on a real install and these tables do not exist
// there. This is a belt-and-suspenders cleanup — a no-op on every real
// deployment, and a tidy-up on any environment where the store was ever
// constructed (e.g. a stray test against a shared DB). Idempotent.
//
// The child table (zt_policy_versions, FK → zt_policies) is dropped first.
var ztPolicyDropUp = `-- Migration 051: drop the dead ZTPolicy tables.
DROP TABLE IF EXISTS zt_policy_versions;
DROP TABLE IF EXISTS zt_policies;
`

// Down recreates the exact schema ZTPolicyStore.initSchema used, for strict
// reversibility — even though nothing consumes these tables.
var ztPolicyDropDown = `-- Migration 051 down: recreate the ZTPolicy tables.
CREATE TABLE IF NOT EXISTS zt_policies (
	id UUID PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	effect VARCHAR(20) NOT NULL CHECK (effect IN ('allow', 'deny')),
	conditions JSONB NOT NULL,
	priority INTEGER DEFAULT 0,
	enabled BOOLEAN DEFAULT true,
	tenant_id VARCHAR(255),
	version INTEGER DEFAULT 1,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	created_by VARCHAR(255),
	updated_by VARCHAR(255),
	metadata JSONB
);
CREATE TABLE IF NOT EXISTS zt_policy_versions (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	policy_id UUID NOT NULL,
	version INTEGER NOT NULL,
	policy_data JSONB NOT NULL,
	change_type VARCHAR(50) NOT NULL,
	changed_by VARCHAR(255),
	change_reason TEXT,
	changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (policy_id) REFERENCES zt_policies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_zt_policies_tenant_id ON zt_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_zt_policies_enabled ON zt_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_zt_policies_priority ON zt_policies(priority DESC);
CREATE INDEX IF NOT EXISTS idx_zt_policies_effect ON zt_policies(effect);
CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_policy_id ON zt_policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_changed_at ON zt_policy_versions(changed_at DESC);
`
```

- [ ] **Step 2: Register the migration in the loader**

In `internal/migrations/loader.go`, the v50 entry ends at line 364 with `},` followed by the slice-closing `}` on line 365. Insert a new entry between them. Change:

```go
		{
			Version:     50,
			Name:        "device_posture_results_upsert_key",
			Description: "Add UNIQUE INDEX device_posture_results(identity_id, check_id) so the agent→device posture bridge upserts one latest row per check. Idempotent.",
			UpSQL:       devicePostureUpsertKeyUp,
			DownSQL:     devicePostureUpsertKeyDown,
		},
	}
}
```

to:

```go
		{
			Version:     50,
			Name:        "device_posture_results_upsert_key",
			Description: "Add UNIQUE INDEX device_posture_results(identity_id, check_id) so the agent→device posture bridge upserts one latest row per check. Idempotent.",
			UpSQL:       devicePostureUpsertKeyUp,
			DownSQL:     devicePostureUpsertKeyDown,
		},
		{
			Version:     51,
			Name:        "drop_zt_policies",
			Description: "Drop the dead ZTPolicy tables (zt_policies, zt_policy_versions). Never wired into any service; absent on real installs. Belt cleanup, idempotent (DROP ... IF EXISTS).",
			UpSQL:       ztPolicyDropUp,
			DownSQL:     ztPolicyDropDown,
		},
	}
}
```

- [ ] **Step 3: Verify it builds and registers**

Run: `cd /home/cmit/openidx && gofmt -w internal/migrations/sql_v51.go internal/migrations/loader.go && go build ./internal/migrations/... && go vet ./internal/migrations/...`
Expected: no output (clean build + vet).

Run: `go test ./internal/migrations/ -count=1 2>&1 | tail -3`
Expected: `ok  github.com/openidx/openidx/internal/migrations` (or `no test files` — either is acceptable; the point is it compiles and the slice is valid).

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/migrations/sql_v51.go internal/migrations/loader.go
git commit -m "feat(migrations): v51 — drop the dead ZTPolicy tables (belt cleanup)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Delete the remaining five ZTPolicy files

With the harness relocated and its old test file removed (Task 1) and the migration in place (Task 2), the ZT code has no remaining dependents. `zt_policy_store_test.go` was already deleted in Task 1; the other five files go here.

**Files:**
- Delete: `internal/governance/zt_policy.go`
- Delete: `internal/governance/zt_policy_handler.go`
- Delete: `internal/governance/zt_policy_store.go`
- Delete: `internal/governance/zt_policy_test.go`
- Delete: `internal/governance/zt_policy_handler_test.go`

- [ ] **Step 1: Delete the files**

```bash
cd /home/cmit/openidx
git rm internal/governance/zt_policy.go \
       internal/governance/zt_policy_handler.go \
       internal/governance/zt_policy_store.go \
       internal/governance/zt_policy_test.go \
       internal/governance/zt_policy_handler_test.go
```

- [ ] **Step 2: Verify the build is clean (no dangling references)**

Run: `cd /home/cmit/openidx && go build ./... 2>&1 | head`
Expected: no output. If the compiler reports an undefined symbol (e.g. a ZT type used somewhere unexpected), STOP — the spec's build-safety assumption is wrong and needs escalation. (Pre-verified: no such references exist.)

Run: `go vet ./internal/governance/... 2>&1 | head`
Expected: no output.

- [ ] **Step 3: Verify no ZT references remain anywhere**

Run: `grep -rn 'ZTPolicy\|zt_policies\|zt_policy_versions\|ConditionGroup\|ZTPolicyEvaluator' internal/ cmd/ --include='*.go'`
Expected: no output (empty). Documentation/spec/plan files under `docs/` may still mention it — that's fine; the grep is scoped to `*.go`.

- [ ] **Step 4: Run the full governance suite**

Run: `cd /home/cmit/openidx && go test ./internal/governance/ -count=1 2>&1 | tail -5`
Expected: `ok  github.com/openidx/openidx/internal/governance`. In particular `TestPolicyRulesRoundTrip` still passes (proves the relocated `setupTestDB` is wired correctly) and the ZT tests are simply gone.

- [ ] **Step 5: Commit**

```bash
cd /home/cmit/openidx
git add -A internal/governance/
git commit -m "refactor(governance): delete the dead ZTPolicy subsystem (G2)

ZTPolicyHandler/NewZTPolicyStore were constructed only in tests; the
zt_policies/zt_policy_versions tables exist in no migration and on no live
install; nothing outside zt_policy*.go references the ZT types, and its
general-ABAC niche is already served by the wired abac-policies surface.
Completes removal of the ZTPolicy subsystem (~4.9k LOC across G2) — code
that looks live (EvaluatePolicies handler, PolicyMiddleware) but is
unreachable. setupTestDB was relocated to
testdb_test.go in a prior commit so G1's TestPolicyRulesRoundTrip keeps its
harness.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Live verification on the box

No runtime behavior changes (the code was dead), but apply the migration and rebuild the governance binary for parity. AUTO_MIGRATE is off on this box, so v51 is applied manually.

**Files:** none (deployment only).

- [ ] **Step 1: Confirm the tables are absent before applying (sanity)**

Run:
```bash
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT to_regclass('public.zt_policies'), to_regclass('public.zt_policy_versions');" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `|` (both NULL — tables don't exist).

- [ ] **Step 2: Apply the v51 Up SQL manually (no-op DROP)**

Run:
```bash
docker exec oidx-pg psql -U openidx -d openidx -c "DROP TABLE IF EXISTS zt_policy_versions; DROP TABLE IF EXISTS zt_policies;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: two `NOTICE: table "..." does not exist, skipping` / `DROP TABLE` lines, no error.

- [ ] **Step 3: Record v51 as applied in the schema_migrations ledger**

First confirm the ledger table name/columns this install uses:
```bash
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%migration%';" 2>&1 | grep -v 'Emulate\|nodocker'
```
Then inspect its columns and the v50 row to copy the exact shape:
```bash
docker exec oidx-pg psql -U openidx -d openidx -c "SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 3;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Insert a matching v51 row mirroring the v50 row's columns (adjust column list to what the table actually has — typically `version`, `name`, `applied_at`):
```bash
docker exec oidx-pg psql -U openidx -d openidx -c "INSERT INTO schema_migrations (version, name, applied_at) VALUES (51, 'drop_zt_policies', now()) ON CONFLICT (version) DO NOTHING;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `INSERT 0 1`. If the ledger table/column names differ, use the actual names observed above. If this install has no migration ledger table, skip this step (note it in the final report).

- [ ] **Step 4: Rebuild and restart the governance binary for parity**

```bash
cd /home/cmit/openidx
go build -o /tmp/oidx-governance-service.new ./cmd/governance-service && \
systemctl --user stop oidx-governance.service && \
cp /tmp/oidx-governance-service.new /home/cmit/oidx-runtime/bin/oidx-governance-service && \
systemctl --user start oidx-governance.service && \
sleep 2 && systemctl --user is-active oidx-governance.service && \
ss -ltnp 2>/dev/null | grep ':8002' | head -1
```
Expected: `active` and a listener on `:8002`.

- [ ] **Step 5: Confirm governance still serves (no regression)**

Run: `curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8002/health`
Expected: `HTTP 200`.

- [ ] **Step 6: No commit** — this task is deployment only. Report the outcomes (table absent → DROP no-op, ledger updated, service healthy) back to the controller.

---

## Notes for the executor
- Tasks are ordered by dependency: **1 → 2 → 3 → 4**. Task 1 must precede Task 3 (harness relocation). Task 2 is independent of 1 but should land before 3 conceptually (the migration documents the removal). Do not reorder 1 and 3.
- This is a deletion: there is no "write a failing test first" for most steps. The test discipline here is *negative* — the suite must stay green and the build must stay clean after each removal, which the verify steps enforce.
- If any `go build`/`go vet` step produces output, treat it as a failure and fix before committing — never commit a red build.
