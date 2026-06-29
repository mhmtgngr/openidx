# v1.8 RLS enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate the already-built, already-`FORCE`'d RLS belt by running the app under a non-owner `openidx_app` Postgres role so tenant isolation actually enforces.

**Architecture:** A migration (+ init-db parity) provisions a `NOSUPERUSER NOBYPASSRLS` runtime role with blanket DML grants; the live box's app `DATABASE_URL` cuts over to it while migrations stay on the owner (`openidx`); verification proves RLS now bites. No policy changes — v37 already wrote the restrictive policies + FORCE.

**Tech Stack:** Go 1.22, the in-repo migration framework (`internal/migrations/sql_vNN.go` + `loader.go`), PostgreSQL roles/RLS, systemd user services.

---

### Task 1: Migration v53 — provision the `openidx_app` runtime role

**Files:**
- Create: `internal/migrations/sql_v53.go`
- Modify: `internal/migrations/loader.go` (append after the v52 entry)

- [ ] **Step 1: Create the migration SQL file**

Create `internal/migrations/sql_v53.go`:

```go
package migrations

// Migration v53 — provision the non-owner application runtime role.
//
// The v37 RLS belt (restrictive pol_<t>_org_scope policies + FORCE ROW LEVEL
// SECURITY on the scoped tables) is inert because the app connects as a
// superuser/BYPASSRLS role, which bypasses RLS. This creates a dedicated
// NOSUPERUSER NOBYPASSRLS runtime role (openidx_app) with DML grants but no
// table ownership, so the FORCE'd policies apply to it. The app cuts its
// DATABASE_URL over to this role; migrations/DDL stay on the owner (openidx).
//
// Passwordless on purpose — the password is set out-of-band at deploy time
// (ALTER ROLE openidx_app PASSWORD ...) so no secret lands in git. Idempotent.
// "GRANT ... ON ALL TABLES" + ALTER DEFAULT PRIVILEGES makes grant-completeness
// hold by construction (RLS still restricts rows; grants only gate table access).
var rlsAppRoleUp = `-- Migration 053: provision the openidx_app runtime role.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT CONNECT ON DATABASE openidx TO openidx_app;
GRANT USAGE ON SCHEMA public TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openidx_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO openidx_app;
`

// Down revokes and drops the role (it owns nothing). Idempotent.
var rlsAppRoleDown = `-- Migration 053 down: drop the openidx_app runtime role.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM openidx_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM openidx_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM openidx_app;
REVOKE ALL ON SCHEMA public FROM openidx_app;
REVOKE ALL ON DATABASE openidx FROM openidx_app;
DROP ROLE IF EXISTS openidx_app;
`
```

- [ ] **Step 2: Register the migration in the loader**

In `internal/migrations/loader.go`, the v52 entry currently ends the slice:

```go
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

Insert a v53 entry between that closing `},` and the slice-closing `}`:

```go
		{
			Version:     52,
			Name:        "reconcile_continuous_verify_columns",
			Description: "Add the init-db-only continuous-verify columns (proxy_sessions.last_verified_at/verification_failures/geo_country/geo_city/idp_id/device_trusted; user_sessions.device_trusted + index) so the continuous session verifier's query works on migrate-based installs. Idempotent; Down is a no-op.",
			UpSQL:       continuousVerifyColumnsUp,
			DownSQL:     continuousVerifyColumnsDown,
		},
		{
			Version:     53,
			Name:        "provision_openidx_app_role",
			Description: "Provision the openidx_app NOSUPERUSER NOBYPASSRLS runtime role with blanket DML grants + default privileges, so the v37 FORCE'd RLS policies enforce once the app cuts its DATABASE_URL over to it. Passwordless (set at deploy). Migrations/DDL stay on the owner. Idempotent.",
			UpSQL:       rlsAppRoleUp,
			DownSQL:     rlsAppRoleDown,
		},
	}
}
```

- [ ] **Step 3: Build, vet, test the migrations package**

Run: `cd /home/cmit/openidx && gofmt -w internal/migrations/sql_v53.go internal/migrations/loader.go && go build ./internal/migrations/... && go vet ./internal/migrations/...`
Expected: no output (clean).

Run: `go test ./internal/migrations/ -count=1 2>&1 | tail -3`
Expected: `ok github.com/openidx/openidx/internal/migrations` (the loader/migration tests compile and the slice is valid). If a test asserts a contiguous version sequence or count, update it per its existing pattern.

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/migrations/sql_v53.go internal/migrations/loader.go
git commit -m "feat(migrations): v53 — provision openidx_app non-owner runtime role for RLS

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `init-db.sql` parity

Fresh installs (the apisix-edge runbook, docker-compose) must also get `openidx_app`. Append the same provisioning to the init script.

**Files:**
- Modify: `deployments/docker/init-db.sql` (append at end)

- [ ] **Step 1: Append the role provisioning**

Append to the end of `deployments/docker/init-db.sql`:

```sql

-- ============================================================================
-- v1.8 RLS: non-owner application runtime role (mirrors migration v53)
-- The app connects as this NOSUPERUSER NOBYPASSRLS role so the FORCE'd RLS
-- policies enforce. Passwordless here — set the password at deploy time
-- (ALTER ROLE openidx_app PASSWORD '...') and point the app DATABASE_URL at it.
-- Migrations/DDL keep using the owner role.
-- ============================================================================
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT CONNECT ON DATABASE openidx TO openidx_app;
GRANT USAGE ON SCHEMA public TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openidx_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO openidx_app;
```

(Note: `init-db.sql` runs after the schema is created, so `ON ALL TABLES` covers the just-created tables. `GRANT CONNECT ON DATABASE openidx` assumes the DB name `openidx` — matches the rest of init-db.)

- [ ] **Step 2: Sanity-check the SQL parses**

Run: `cd /home/cmit/openidx && docker exec -i oidx-pg psql -U openidx -d openidx -v ON_ERROR_STOP=1 --single-transaction -f - < /dev/null 2>&1; echo "psql reachable"` then validate the appended block in a throwaway transaction:
```bash
docker exec -i oidx-pg psql -U openidx -d openidx 2>&1 <<'SQL' | grep -v 'Emulate\|nodocker'
BEGIN;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openidx_app') THEN CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$;
GRANT CONNECT ON DATABASE openidx TO openidx_app;
GRANT USAGE ON SCHEMA public TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openidx_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO openidx_app;
ROLLBACK;
SQL
```
Expected: `CREATE ROLE` / `GRANT` / `ALTER DEFAULT PRIVILEGES` lines, no `ERROR`, then `ROLLBACK` (the throwaway tx is discarded). This validates the exact SQL without persisting it (Task 3 applies it for real via the migration).

- [ ] **Step 3: Commit**

```bash
cd /home/cmit/openidx
git add deployments/docker/init-db.sql
git commit -m "feat(deploy): provision openidx_app runtime role in init-db (v53 parity)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Live cutover + verification (the box)

Apply v53 as the owner, set the password, cut the app over, and prove RLS bites. No commit (deployment + runtime config). The box's migration ledger is applied ad hoc (as v50/v52 were this session), so apply v53's SQL directly via psql as the owner rather than running the whole `migrate up` chain.

**Files:** none committed (edits to `~/.config/oidx/common.env`, `~/oidx-runtime/run-access.sh`).

- [ ] **Step 1: Apply v53 Up as the owner + set the password**

```bash
APPPW=$(openssl rand -hex 24); echo "$APPPW" > /tmp/oidx-app-pw
docker exec -i oidx-pg psql -U openidx -d openidx -v ON_ERROR_STOP=1 2>&1 <<SQL | grep -v 'Emulate\|nodocker'
DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openidx_app') THEN CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END \$\$;
GRANT CONNECT ON DATABASE openidx TO openidx_app;
GRANT USAGE ON SCHEMA public TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openidx_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO openidx_app;
ALTER ROLE openidx_app PASSWORD '${APPPW}';
SQL
echo "=== role attributes (must be f|f) ==="
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT rolsuper||'|'||rolbypassrls||'|'||rolcanlogin FROM pg_roles WHERE rolname='openidx_app';" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: grant lines, no error; role attributes `f|f|t` (NOSUPERUSER, NOBYPASSRLS, LOGIN).

- [ ] **Step 2: Prove RLS bites under the new role (before cutting services over)**

```bash
APPPW=$(cat /tmp/oidx-app-pw)
# In-container psql reaches Postgres on the container-internal port 5432
# (the host's 55432 is a port mapping that doesn't exist inside the container).
APPURL_CTR="postgresql://openidx_app:${APPPW}@127.0.0.1:5432/openidx?sslmode=disable"
ORG='00000000-0000-0000-0000-000000000010'
echo "--- no GUC → expect 0 (RLS fail-closed) ---"
docker exec oidx-pg psql "$APPURL_CTR" -tA -c "SELECT count(*) FROM users;" 2>&1 | grep -v 'Emulate\|nodocker'
echo "--- org-scoped → expect that org's count ---"
docker exec oidx-pg psql "$APPURL_CTR" -tA -c "SET app.org_id='$ORG'; SELECT count(*) FROM users;" 2>&1 | grep -v 'Emulate\|nodocker'
echo "--- bypass → expect all rows ---"
docker exec oidx-pg psql "$APPURL_CTR" -tA -c "SET app.bypass_rls='on'; SELECT count(*) FROM users;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `0`, then the default org's user count (non-zero), then all users (e.g. 11). If the first is not 0, STOP — RLS still isn't enforcing (role mis-created) and cutover must not proceed.

- [ ] **Step 3: Cut the app's DATABASE_URL over to openidx_app**

```bash
APPPW=$(cat /tmp/oidx-app-pw)
APPURL="postgres://openidx_app:${APPPW}@localhost:55432/openidx?sslmode=disable"
# common.env (the 7 systemd services that use it)
sed -i "s#^DATABASE_URL=.*#DATABASE_URL=${APPURL}#" /home/cmit/.config/oidx/common.env
# run-access.sh (the access service's wrapper has its own export)
sed -i "s#^export DATABASE_URL=.*#export DATABASE_URL=\"${APPURL}\"#" /home/cmit/oidx-runtime/run-access.sh
echo "common.env:"; grep '^DATABASE_URL' /home/cmit/.config/oidx/common.env | sed 's#:[^:@]*@#:***@#'
echo "run-access.sh:"; grep '^export DATABASE_URL' /home/cmit/oidx-runtime/run-access.sh | sed 's#:[^:@]*@#:***@#'
```
Expected: both show `openidx_app@...` (password masked). The `cmd/migrate` runner is unaffected — it's invoked with the owner DSN when migrations are run.

- [ ] **Step 4: Restart all 8 services + health-check**

```bash
systemctl --user restart oidx-identity oidx-governance oidx-provisioning oidx-audit oidx-admin-api oidx-oauth oidx-gateway oidx-access
sleep 4
for p in 8001 8002 8003 8004 8005 8006 8007 8008; do printf ":%s=%s " "$p" "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$p/health 2>/dev/null)"; done; echo
echo "=== scan logs for permission/role errors (want none) ==="
grep -iE 'permission denied|must be owner|role .openidx_app.|password authentication failed' /tmp/oidx-logs/*.log | tail -20 || echo "no permission/auth errors"
```
Expected: all eight `=200`; no permission/auth errors. A `permission denied for table X` means a grant gap (shouldn't happen with the blanket grant, but if it does, that table is in a non-`public` schema — grant it explicitly and note it). A `password authentication failed` means the DSN/password is wrong — recheck Step 1/3.

- [ ] **Step 5: End-to-end smoke — representative read+write per service + bypass paths**

```bash
# Reads through the running services (DB-backed health/list endpoints):
for u in \
  "http://localhost:8002/api/v1/governance/policies" \
  "http://localhost:8004/api/v1/audit/events?limit=1" \
  "http://localhost:8005/api/v1/dashboard" ; do
  printf "%s -> %s\n" "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)"
done
echo "=== bypass paths still work? Relations Doctor (uses WithBypassRLS) ==="
curl -s -o /dev/null -w "doctor=%{http_code}\n" "http://localhost:8007/api/v1/access/health/relations" 2>/dev/null
echo "=== continuous-verify driver query under bypass (should run, not 0-by-RLS) ==="
docker exec oidx-pg psql "postgresql://openidx_app:$(cat /tmp/oidx-app-pw)@127.0.0.1:5432/openidx?sslmode=disable" -tA -c "SET app.bypass_rls='on'; SELECT count(*) FROM proxy_sessions;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: endpoints return their normal codes (200, or 401/403 if auth-gated — NOT 500; a 500 with a DB error means a grant/role problem). Doctor returns its normal code. The bypass count query returns all rows (proves bypass path unaffected by the role). Auth-gated endpoints returning 401/403 is fine — the point is no 500/DB-permission failures. Write-path confidence: the services completing startup + the governance/audit reads exercising the pool under `openidx_app` is the core signal; if a deeper write check is wanted, create+delete a throwaway proxy route via the admin API.

- [ ] **Step 6: Record the outcome / rollback note**

Report: role attributes `f|f|t`; RLS bite proof (0 / org / all); all 8 services healthy on `openidx_app`; no permission errors; Doctor + bypass intact. 

**Rollback (if anything fails):** restore the owner DSN and restart —
```bash
sed -i 's#^DATABASE_URL=.*#DATABASE_URL=postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable#' /home/cmit/.config/oidx/common.env
sed -i 's#^export DATABASE_URL=.*#export DATABASE_URL="postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable"#' /home/cmit/oidx-runtime/run-access.sh
systemctl --user restart oidx-identity oidx-governance oidx-provisioning oidx-audit oidx-admin-api oidx-oauth oidx-gateway oidx-access
```
The `openidx_app` role + grants are harmless to leave. Remove `/tmp/oidx-app-pw` after recording the password somewhere durable if keeping the cutover.

- [ ] **Step 7: No commit** — deployment only.

---

## Notes for the executor
- Dependency order **1 → 2 → 3**. Task 3 applies the same SQL Task 1 codifies; do not run Task 3 before Task 1's SQL is finalized.
- Tasks 1–2 are code/SQL (subagent-friendly). **Task 3 is live box ops on the running stack** — highest blast radius of the epic; run it directly, gate on the Step 2 RLS-bite proof before cutting services over, and keep the Step 6 rollback ready.
- The password lives only in `/tmp/oidx-app-pw` during the task + in the two env files (mode-protected, not in git). Never commit it.
- Do NOT change any RLS policy or the FORCE/ENABLE state — v37 owns that and is correct.
- Do NOT point `cmd/migrate` at `openidx_app` — migrations need the owner (DDL).
