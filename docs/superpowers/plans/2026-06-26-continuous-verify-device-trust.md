# Close the continuous-verify device-trust gap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unbreak the continuous session verifier on migrate-based installs (it queries `proxy_sessions` columns that exist only in `init-db.sql`) and make it re-derive device trust from the live D2 signal instead of an unwritten column.

**Architecture:** A migration reconciles the init-db-only continuous-verify columns onto `proxy_sessions`/`user_sessions` (the v42–v51 reconcile pattern). The verifier then computes `DeviceTrusted` per session via the existing `deviceTrusted` reader rather than the stale scanned column.

**Tech Stack:** Go 1.22, the in-repo migration framework (`internal/migrations/sql_vNN.go` + `loader.go`), pgx v5.

---

### Task 1: Migration v52 — reconcile continuous-verify columns

**Files:**
- Create: `internal/migrations/sql_v52.go`
- Modify: `internal/migrations/loader.go` (append after the v51 entry)

- [ ] **Step 1: Create the migration SQL file**

Create `internal/migrations/sql_v52.go`:

```go
package migrations

// Migration v52 — reconcile the continuous-verification columns that exist only
// in init-db.sql onto migrate-based installs. The continuous session verifier
// (internal/access/continuous_verify.go) selects proxy_sessions.device_trusted
// and filters on proxy_sessions.last_verified_at; on installs provisioned by the
// migration runner (not init-db.sql) those columns are absent and the verifier's
// query errors every run. This mirrors init-db.sql (lines ~1614-1619, 2153-2160).
// Same init-db<->migrations gap reconciled for other tables in v42-v45. Idempotent.
var continuousVerifyColumnsUp = `-- Migration 052: reconcile continuous-verify columns.
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(10);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_city VARCHAR(255);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
`

// Down is intentionally a no-op. The Up uses ADD COLUMN IF NOT EXISTS, so on an
// init-db-provisioned install these columns already existed before this migration
// ran — it cannot know whether it created them or they pre-existed. Dropping them
// on rollback would re-break continuous-verify on exactly those installs (and
// idp_id is depended on across the access service). A gap-reconcile migration is
// not faithfully reversible by column-drop; the columns are harmless to leave.
var continuousVerifyColumnsDown = `-- Migration 052 down: intentionally a no-op (see sql_v52.go).
SELECT 1;
`
```

- [ ] **Step 2: Register the migration in the loader**

In `internal/migrations/loader.go`, the v51 entry currently ends the slice:

```go
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

Insert a v52 entry between the v51 entry's closing `},` and the slice-closing `}`:

```go
		{
			Version:     51,
			Name:        "drop_zt_policies",
			Description: "Drop the dead ZTPolicy tables (zt_policies, zt_policy_versions). Never wired into any service; absent on real installs. Belt cleanup, idempotent (DROP ... IF EXISTS).",
			UpSQL:       ztPolicyDropUp,
			DownSQL:     ztPolicyDropDown,
		},
		{
			Version:     52,
			Name:        "reconcile_continuous_verify_columns",
			Description: "Add the init-db-only continuous-verify columns (proxy_sessions.last_verified_at/verification_failures/geo_country/geo_city/idp_id/device_trusted; user_sessions.device_trusted + index) so the continuous session verifier's query works on migrate-based installs. Idempotent; Down is a no-op.",
			UpSQL:       continuousVerifyColumnsUp,
			DownSQL:     continuousVerifyColumnsDown,
		},
	}
}
```

- [ ] **Step 3: Verify it builds and registers**

Run: `cd /home/cmit/openidx && gofmt -w internal/migrations/sql_v52.go internal/migrations/loader.go && go build ./internal/migrations/... && go vet ./internal/migrations/...`
Expected: no output (clean build + vet).

Run: `go test ./internal/migrations/ -count=1 2>&1 | tail -3`
Expected: `ok github.com/openidx/openidx/internal/migrations` (or `[no test files]` — either is fine; the point is it compiles and the slice is valid).

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/migrations/sql_v52.go internal/migrations/loader.go
git commit -m "feat(migrations): v52 — reconcile continuous-verify columns (init-db gap)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Verifier re-derives device trust from the live signal

**Files:**
- Modify: `internal/access/continuous_verify.go`

The verify loop builds a `ProxySession` and an `AccessContext`, both currently set `DeviceTrusted: sess.DeviceTrusted` — the value scanned from `proxy_sessions.device_trusted`, which the forward-auth path never persists (so it's stale/`false`). Recompute it live with the same D2 reader the forward-auth path uses.

- [ ] **Step 1: Insert the live recomputation before the `proxySession` build**

In `internal/access/continuous_verify.go`, find this line (the start of the per-session `ProxySession` build inside the `for _, sess := range sessions` loop):

```go
		proxySession := &ProxySession{
```

Replace it with:

```go
		// Re-derive device trust from the live known_devices signal (same reader
		// as the forward-auth path) rather than the persisted column, so a device
		// that was un-trusted since login is caught on re-verification.
		trusted := cv.svc.deviceTrusted(ctx, sess.UserID, sess.IPAddress, sess.UserAgent)

		proxySession := &ProxySession{
```

- [ ] **Step 2: Use the recomputed value at both sites**

In the same file, replace BOTH occurrences of the exact text `sess.DeviceTrusted,` with `trusted,`. There are exactly two — one in the `&ProxySession{...}` literal and one in the `&AccessContext{...}` literal. (Use a replace-all on the literal `sess.DeviceTrusted,`; the surrounding `DeviceTrusted:` field name and its alignment are preserved because only the value token changes.)

After this edit, the struct field `sessionToVerify.DeviceTrusted` and its scan are still present but no longer drive the decision — that is intentional and harmless (the column now exists post-v52, so the scan still succeeds). Do NOT change the driver SQL or the scan in this task.

- [ ] **Step 3: Build and vet**

Run: `cd /home/cmit/openidx && gofmt -w internal/access/continuous_verify.go && go build ./... && go vet ./internal/access/...`
Expected: no output (clean). If `go vet`/build complains that `trusted` is declared and not used, it means Step 2 didn't replace both sites — re-check that both `sess.DeviceTrusted,` became `trusted,`.

- [ ] **Step 4: Run the access suite**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -count=1 2>&1 | tail -5`
Expected: `ok github.com/openidx/openidx/internal/access` (testcontainers; ~30-90s).

- [ ] **Step 5: Commit**

```bash
cd /home/cmit/openidx
git add internal/access/continuous_verify.go
git commit -m "feat(access): continuous-verify re-derives device trust from the live signal (not the stale column)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Live verification on the box

Apply v52, redeploy access, and prove the verifier runs without the column error. No commit.

**Files:** none (deployment only).

- [ ] **Step 1: Confirm the columns are missing, then apply v52's Up SQL**

```bash
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT 'before: '||count(*)||' of 6 present' FROM information_schema.columns WHERE table_name='proxy_sessions' AND column_name IN ('last_verified_at','verification_failures','geo_country','geo_city','idp_id','device_trusted');" 2>&1 | grep -v 'Emulate\|nodocker'
docker exec oidx-pg psql -U openidx -d openidx 2>&1 <<'SQL' | grep -v 'Emulate\|nodocker'
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(10);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_city VARCHAR(255);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
SQL
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT 'after: '||count(*)||' of 6 present' FROM information_schema.columns WHERE table_name='proxy_sessions' AND column_name IN ('last_verified_at','verification_failures','geo_country','geo_city','idp_id','device_trusted');" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `before: 1 of 6 present` → `after: 6 of 6 present`.

- [ ] **Step 2: Rebuild + restart access**

```bash
cd /home/cmit/openidx
go build -o /tmp/oidx-access-service.new ./cmd/access-service && \
systemctl --user stop oidx-access.service && \
cp /tmp/oidx-access-service.new /home/cmit/oidx-runtime/bin/oidx-access-service && \
systemctl --user start oidx-access.service && sleep 3 && \
systemctl --user is-active oidx-access.service && ss -ltnp 2>/dev/null | grep ':8007' | head -1
```
Expected: `active`, listener on :8007.

- [ ] **Step 3: Prove the verifier's driver query now runs (primary check — independent of whether the ticker is enabled)**

The substantive break was that the driver SELECT referenced non-existent columns and errored before processing any row. Run that exact query against the box DB — after v52 it must execute without a "column does not exist" error (returning zero or more rows is success; the point is it no longer errors):

```bash
docker exec oidx-pg psql -U openidx -d openidx 2>&1 <<'SQL' | grep -v 'Emulate\|nodocker'
SELECT s.id, s.user_id, s.ip_address, s.user_agent, s.route_id,
       s.device_fingerprint, s.risk_score, s.device_trusted,
       r.id as route_id, r.reverify_interval, s.org_id
FROM proxy_sessions s
JOIN proxy_routes r ON s.route_id = r.id AND r.org_id = s.org_id
WHERE s.revoked = false
  AND s.expires_at > NOW()
  AND r.reverify_interval > 0
  AND (s.last_verified_at IS NULL
       OR s.last_verified_at < NOW() - (r.reverify_interval || ' seconds')::INTERVAL)
LIMIT 100;
SQL
```
Expected: a normal result set (likely `(0 rows)` since no route has `reverify_interval > 0`), and crucially **no** `ERROR: column "..." does not exist`. This directly proves Component 1 fixed the break.

- [ ] **Step 4: (Best-effort) observe the live ticker if it's enabled**

Check whether the verifier is actually running on this box, and if so confirm its log is clean of the old error:

```bash
grep -iE 'Continuous session verifier started|Starting continuous session verifier' /tmp/oidx-logs/access.log | tail -2 || echo "verifier not enabled on this box (ContinuousVerifyEnabled off) — skip ticker observation"
echo "--- any reverify column/query errors in the log? (want NONE) ---"
grep -iE 'does not exist|Failed to query sessions for reverification' /tmp/oidx-logs/access.log | tail -5 || echo "no column/query errors"
```
Expected: no `does not exist` / `Failed to query sessions for reverification` lines. If the verifier isn't enabled, Step 3 already provides the proof; note that in the report.

- [ ] **Step 5: No commit** — report outcomes (columns 1→6 present, access healthy, the verifier driver query runs without the column error, ticker status noted). No box cleanup is needed — Step 3 only ran a SELECT, and the v52 columns are intentionally left in place (they are the migration's deliverable).

---

## Notes for the executor
- Dependency order **1 → 2 → 3**. Task 2's recompute is meaningless until Task 1's columns exist (the verifier query would still error). Keep the order.
- Task 1 is a standard migration (build/register, no bespoke test — matches v42–v51). Task 2 is a 3-line code change verified by build + the access suite; the end-to-end behaviour is Task 3 (live).
- The driver SQL and scan in `continuous_verify.go` are deliberately left unchanged in Task 2 — the column now exists, so they keep working; only the *source* of the `DeviceTrusted` value used for the decision changes.
- Never commit a red build. If `trusted` is reported unused after Task 2, both `sess.DeviceTrusted,` sites were not replaced — fix before committing.
- Out of scope (do NOT implement): persisting geo/verification_failures writes; changing the verifier's decision logic; enabling reverify on real routes.
