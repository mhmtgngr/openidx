# Compose: migrations own the schema + `openidx_app` cutover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a fresh `docker compose up` produce the same RLS-enforced,
`openidx_app`-scoped deployment the box runs, by having migrations own the schema
(retiring `init-db.sql` as the schema source) and cutting the app role over.

**Architecture:** postgres first-init runs a *minimal* `bootstrap.sql` (passwordless
`openidx_app` role) + a `zz-` password hook → a one-shot `migrate` service builds the
full v1–v67 schema + RLS belt + login seed as the superuser → a one-shot `seed`
service applies the functional-delta `seed.sql` (role_permissions + default policies)
under `app.bypass_rls` → the 8 app services connect as the non-owner `openidx_app`
role so FORCE-RLS enforces.

**Tech Stack:** docker compose (v2), Postgres 16, `cmd/migrate` (built via
`Dockerfile.service` `SERVICE_NAME=migrate`), Go integration test (pgx v5).

**Spec:** `docs/superpowers/specs/2026-07-04-compose-migrations-own-schema-cutover-design.md`

**Branch:** `feat/compose-migrations-own-schema` (already created; spec committed).

---

## File Structure

**PR 1 — schema via migrations + seed (app stays superuser):**
- Create: `deployments/docker/seed.sql` — functional-delta bootstrap seed.
- Create: `deployments/docker/bootstrap.sql` — minimal init (role only).
- Modify: `deployments/docker/docker-compose.yml` — swap init-db mount → bootstrap;
  add `migrate` + `seed` services; add `depends_on: seed` to the 8 app services.
- Modify: `deployments/docker/docker-compose.prod.yml` — same wiring (7 app services).
- Delete: `deployments/docker/init-db.sql` (retired as schema source).
- Modify/Delete: `internal/migrations/initdb_parity_test.go` — retire (init-db no
  longer defines tables; migrations are the sole source).
- Create: `test/integration/compose_seed_test.go` — throwaway-DB e2e (migrate + seed
  + RLS fail-closed).

**PR 2 — `openidx_app` cutover (RLS enforces):**
- Modify: both compose files — 8/7 app-service `DATABASE_URL` → `openidx_app`.
- Create: `deployments/docker/set-app-role-password.sh` — `zz-` password hook.
- Modify: both compose files — mount the hook + add `OPENIDX_APP_PASSWORD` to
  postgres `environment`.
- Modify: `deployments/docker/.env` and `deployments/docker/.env.production` — add
  `OPENIDX_APP_PASSWORD`.

---

# PR 1 — schema via migrations + seed

### Task 1: Extract `seed.sql` from init-db (BEFORE reducing init-db)

**Files:**
- Create: `deployments/docker/seed.sql`
- Source (read-only): `deployments/docker/init-db.sql`

The functional delta migrations don't already provide. Migrations already seed the
default org, admin user, `admin-console` client, roles, permissions, user_roles,
system_settings. seed.sql adds **only**: `role_permissions` (RBAC completeness) and
the default policy/config rows. Demo data is intentionally excluded.

- [ ] **Step 1: Create the file header + bypass guard**

```sql
-- deployments/docker/seed.sql
-- Bootstrap seed for docker-compose: the functional delta the migrations do NOT
-- already seed. migrate-from-empty already creates the default org, admin user,
-- admin-console OAuth client, roles, permissions, user_roles, system_settings.
-- This file adds role_permissions (granular RBAC for non-admin roles; admin is
-- privileged by role name) and default policy/config rows.
--
-- Runs as the superuser AFTER `migrate up`, with app.bypass_rls set so the FORCE'd
-- RLS belt permits inserts into org-scoped tables. Scoped tables (role_permissions,
-- privacy_retention_policies, tenant_branding) have a DEFAULT of the default-org
-- UUID (migration v36), so INSERTs that omit org_id still land in the default org.
--
-- EXCLUDED (sample data, not required for a functional install): demo users
-- (jsmith/jdoe/bwilson), demo proxy_routes, demo applications, ziti_user_sync demo.
--
-- Idempotent: every INSERT is ON CONFLICT DO NOTHING.
SET app.bypass_rls = 'on';
```

- [ ] **Step 2: Copy the delta INSERT blocks verbatim from `init-db.sql`**

Copy these exact blocks (by current line range) from `init-db.sql` into `seed.sql`,
in this order. Each is a straight `INSERT` — paste verbatim, then ensure each ends
with `ON CONFLICT DO NOTHING;` (add it if the source block lacks it):

| Source lines | Table | org-scoped? |
|---|---|---|
| 2433–2436 | `role_permissions` (admin → all perms) | yes (DEFAULT covers) |
| 2438–2449 | `role_permissions` (developer) | yes |
| 2450–2461 | `role_permissions` (manager) | yes |
| 2462–2469 | `role_permissions` (auditor) | yes |
| 2470–end-of-stmt | `role_permissions` (user) | yes |
| 1559–end-of-stmt | `posture_check_types` | no |
| 1865–end-of-stmt | `risk_policies` | no |
| 2891–end-of-stmt | `ispm_rules` | no |
| 3124–end-of-stmt | `lifecycle_policies` | no |
| 3395–3399 | `tenant_branding` (sets org_id explicitly) | yes |
| 3400–3405 | `privacy_retention_policies` | yes (DEFAULT covers) |
| 3406–end-of-stmt | `notification_routing_rules` | no |

For each block: read the full statement in `init-db.sql` (it may span more lines
than the start line shown — read until the terminating `;`), paste it, and confirm
the trailing `ON CONFLICT DO NOTHING`. The `role_permissions` blocks already use
`ON CONFLICT DO NOTHING` (the admin block at 2433 does `SELECT … FROM permissions ON
CONFLICT DO NOTHING`); the `VALUES` blocks need it appended if absent.

- [ ] **Step 3: Verify seed.sql applies cleanly on a migrated DB**

```bash
PROBE=seed_check_$(date +%s)
docker exec oidx-pg psql -U openidx -d postgres -c "CREATE DATABASE $PROBE;"
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/$PROBE?sslmode=disable" go run ./cmd/migrate up
docker exec -i oidx-pg psql -U openidx -d $PROBE -v ON_ERROR_STOP=1 < deployments/docker/seed.sql
docker exec oidx-pg psql -U openidx -d $PROBE -tAc "SELECT 'role_permissions='||count(*) FROM role_permissions;"
docker exec oidx-pg psql -U openidx -d $PROBE -tAc "SELECT 'risk_policies='||count(*) FROM risk_policies;"
docker exec oidx-pg psql -U openidx -d postgres -c "DROP DATABASE $PROBE;"
```
Expected: seed applies with exit 0; `role_permissions` ≥ 5, `risk_policies` ≥ 1.
(Run against `oidx-pg` requires `dangerouslyDisableSandbox`.)

- [ ] **Step 4: Commit**

```bash
git add deployments/docker/seed.sql
git commit -m "feat(compose): seed.sql — functional-delta bootstrap (role_permissions + policies)"
```

### Task 2: Create minimal `bootstrap.sql`

**Files:**
- Create: `deployments/docker/bootstrap.sql`

- [ ] **Step 1: Write the file** (role only — migrations create every table; v53
  re-creates the role idempotently and does the grants when `migrate` runs. The role
  must exist here so the `zz-` password hook (PR2) can `ALTER` it pre-migrate.)

```sql
-- deployments/docker/bootstrap.sql
-- Minimal first-init bootstrap for docker-compose. Migrations own the schema
-- (cmd/migrate builds v1–v67 as a one-shot service after postgres is healthy), so
-- this file creates ONLY the passwordless openidx_app runtime role — it must exist
-- at initdb time so the zz-set-app-role-password.sh hook can ALTER its password
-- before the app services start. Migration v53 re-creates the role idempotently and
-- grants it DML; those grants are intentionally NOT duplicated here (no tables exist
-- yet at first-init). gen_random_uuid() is Postgres core (16); no extension needed.
DO
$$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO openidx_app', current_database());
END
$$;
GRANT USAGE ON SCHEMA public TO openidx_app;
```

- [ ] **Step 2: Commit**

```bash
git add deployments/docker/bootstrap.sql
git commit -m "feat(compose): minimal bootstrap.sql (passwordless openidx_app role)"
```

### Task 3: Add `migrate` + `seed` one-shot services and swap the init mount

**Files:**
- Modify: `deployments/docker/docker-compose.yml`
- Modify: `deployments/docker/docker-compose.prod.yml`

- [ ] **Step 1: In `docker-compose.yml`, swap the postgres init mount** — replace
  the `init-db.sql` mount line with `bootstrap.sql` (keep the two Guacamole mounts):

```yaml
      - ./bootstrap.sql:/docker-entrypoint-initdb.d/00-bootstrap.sql:ro
      - ./init-guacamole.sh:/docker-entrypoint-initdb.d/00-init-guacamole.sh:ro
      - ./init-guacamole.sql:/docker-entrypoint-initdb.d/guacamole-schema.sql:ro
```
(The `00-` prefix on bootstrap sorts before the Guacamole scripts and before the
`zz-` password hook added in PR2.)

- [ ] **Step 2: Add the `migrate` and `seed` services** (place after the `postgres`
  service block, before `redis`):

```yaml
  migrate:
    build:
      context: ../..
      dockerfile: deployments/docker/Dockerfile.service
      args:
        SERVICE_NAME: migrate
    container_name: openidx-migrate
    command: ["up"]
    environment:
      - DATABASE_URL=postgres://openidx:${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required - run scripts/generate-secrets.sh}@postgres:5432/openidx?sslmode=${DATABASE_SSL_MODE:-disable}
    depends_on:
      postgres:
        condition: service_healthy
    restart: "no"
    healthcheck:
      disable: true
    networks:
      - openidx-network

  seed:
    image: postgres:16-alpine
    container_name: openidx-seed
    entrypoint: ["sh", "-c", "psql \"$$DATABASE_URL\" -v ON_ERROR_STOP=1 -f /seed/seed.sql"]
    environment:
      - DATABASE_URL=postgres://openidx:${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required - run scripts/generate-secrets.sh}@postgres:5432/openidx?sslmode=${DATABASE_SSL_MODE:-disable}
    volumes:
      - ./seed.sql:/seed/seed.sql:ro
    depends_on:
      migrate:
        condition: service_completed_successfully
    restart: "no"
    healthcheck:
      disable: true
    networks:
      - openidx-network
```

- [ ] **Step 3: Add `depends_on: seed` to each of the 8 app services** — for
  `identity-service`, `governance-service`, `provisioning-service`, `audit-service`,
  `admin-api`, `gateway-service`, `oauth-service`, `access-service`, add under their
  existing `depends_on:` map:

```yaml
      seed:
        condition: service_completed_successfully
```
(Keep their existing `postgres`/`redis`/`mailpit` conditions. `depends_on` is a map
here, so add the key — do not convert to list form.)

- [ ] **Step 4: Repeat Steps 1–3 in `docker-compose.prod.yml`** (7 app services;
  it has no `access-service`. Verify the prod file's postgres mount + service names
  first — the env var interpolation and `depends_on` style match the dev file.)

- [ ] **Step 5: Validate both compose files**

```bash
cd deployments/docker
POSTGRES_PASSWORD=x REDIS_PASSWORD=x docker compose -f docker-compose.yml config >/dev/null && echo "dev OK"
POSTGRES_PASSWORD=x REDIS_PASSWORD=x docker compose -f docker-compose.prod.yml config >/dev/null && echo "prod OK"
```
Expected: both print OK (config validates: services, `depends_on` conditions, env
interpolation). If `docker compose` is unavailable, use `docker-compose config`.

- [ ] **Step 6: Commit**

```bash
git add deployments/docker/docker-compose.yml deployments/docker/docker-compose.prod.yml
git commit -m "feat(compose): migrate + seed one-shot services; bootstrap mount; app depends_on seed"
```

### Task 4: Retire `init-db.sql` + its parity tests

**Files:**
- Delete: `deployments/docker/init-db.sql`
- Modify/Delete: `internal/migrations/initdb_parity_test.go`

- [ ] **Step 1: Confirm no other consumer references `init-db.sql`**

```bash
grep -rn "init-db.sql" --include=*.go --include=*.yml --include=*.yaml --include=Makefile --include=*.sh . | grep -v docs/
```
Expected after Task 3: only the parity test (and the compose files, now swapped).
If anything else references it (Makefile target, CI, other scripts), update those
references in this step before deleting.

- [ ] **Step 2: Delete init-db.sql and retire the parity tests** (init-db no longer
  defines tables, so `TestInitDBParity`/`TestInitDBColumnParity` have no subject —
  migrations are the sole schema source, which is the whole point of this change):

```bash
git rm deployments/docker/init-db.sql
git rm internal/migrations/initdb_parity_test.go
```
(If the test file contains other still-relevant tests, instead delete only the two
parity test functions + their helpers and keep the file. Check first:
`grep -nE '^func Test' internal/migrations/initdb_parity_test.go`.)

- [ ] **Step 3: Verify the migrations package still builds + tests pass**

```bash
go build ./... && go test ./internal/migrations/ 2>&1 | tail -20
```
Expected: build clean; migrations tests pass (minus the retired parity tests).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(compose): retire init-db.sql as schema source (+ its parity tests)

Migrations are now the sole schema source. Layering migrations on init-db was
dead (v29 ziti_certificates ordering) and init-db.sql was itself broken
(NOW() in an index predicate). migrate-from-empty is clean to v67."
```

### Task 5: DB-level e2e integration test (throwaway DB → migrate → seed → RLS)

**Files:**
- Create: `test/integration/compose_seed_test.go`
- Reference: `test/integration/cross_org_test.go` (`integrationDSN`, `rlsRolePool`)

- [ ] **Step 1: Write the test.** It creates a throwaway DB, migrates it via
  `migrations.NewMigrator(...).MigrateTo(ctx, -1)` (same call `cmd/migrate up`
  makes), applies `seed.sql`, and asserts the migrated+seeded state + RLS fail-closed
  for a NOSUPERUSER role. It uses a dedicated throwaway role (never the shared
  `openidx_app`), mirroring `rlsRolePool`.

```go
//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mhmtgngr/openidx/internal/migrations"
)

// TestComposeMigrateSeedProducesRLSInstall proves the compose model
// (migrate-from-empty + seed.sql) yields a login-capable, RLS-enforced schema:
// migrations own the schema, seed.sql fills the functional delta, and a NOSUPERUSER
// role sees 0 rows on a scoped table without an org GUC (fail-closed) but rows with
// bypass. Uses a throwaway DB so it is self-contained and mutates nothing shared.
func TestComposeMigrateSeedProducesRLSInstall(t *testing.T) {
	adminDSN := integrationDSN(t) // skips if no DB
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 1. Create a throwaway DB via the admin connection.
	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	defer admin.Close()
	dbName := fmt.Sprintf("compose_seed_test_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err, "create throwaway DB")
	t.Cleanup(func() {
		c, e := pgxpool.New(context.Background(), adminDSN)
		if e == nil {
			defer c.Close()
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		}
	})

	// DSN for the throwaway DB (swap the path on the admin DSN).
	u, err := url.Parse(adminDSN)
	require.NoError(t, err)
	u.Path = "/" + dbName
	probeDSN := u.String()

	// 2. Migrate to latest (== `cmd/migrate up`).
	probe, err := pgxpool.New(ctx, probeDSN)
	require.NoError(t, err)
	defer probe.Close()
	require.NoError(t, migrations.NewMigrator(probe, zap.NewNop()).MigrateTo(ctx, -1),
		"migrate-from-empty must reach latest cleanly")

	// 3. Login bootstrap is present from migrations alone.
	assertCount(t, probe, "SELECT count(*) FROM users WHERE username='admin' AND password_hash <> ''", 1, "admin user")
	assertCount(t, probe, "SELECT count(*) FROM oauth_clients WHERE client_id='admin-console'", 1, "admin-console client")
	assertAtLeast(t, probe, "SELECT count(*) FROM user_roles ur JOIN users u ON u.id=ur.user_id JOIN roles r ON r.id=ur.role_id WHERE u.username='admin' AND r.name='admin'", 1, "admin holds admin role")

	// 4. Apply seed.sql (functional delta).
	seedSQL, err := os.ReadFile("../../deployments/docker/seed.sql")
	require.NoError(t, err)
	_, err = probe.Exec(ctx, string(seedSQL))
	require.NoError(t, err, "seed.sql must apply cleanly")
	assertAtLeast(t, probe, "SELECT count(*) FROM role_permissions", 5, "role_permissions seeded")

	// 5. RLS is FORCE'd and fails closed for a NOSUPERUSER role without an org GUC.
	var forced bool
	require.NoError(t, probe.QueryRow(ctx, "SELECT relforcerowsecurity FROM pg_class WHERE relname='users'").Scan(&forced))
	require.True(t, forced, "users must be FORCE-RLS")

	rolePool := throwawayRolePool(t, probe, probeDSN)
	defer rolePool.Close()
	var n int
	require.NoError(t, rolePool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n))
	require.Equal(t, 0, n, "no-GUC query as NOSUPERUSER must see 0 rows (fail-closed)")
}

func assertCount(t *testing.T, db *pgxpool.Pool, q string, want int, what string) {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(context.Background(), q).Scan(&n))
	require.Equal(t, want, n, what)
}

func assertAtLeast(t *testing.T, db *pgxpool.Pool, q string, min int, what string) {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(context.Background(), q).Scan(&n))
	require.GreaterOrEqual(t, n, min, what)
}

// throwawayRolePool creates a dedicated NOSUPERUSER role scoped to THIS throwaway DB
// and returns a pool connected as it. Never touches the shared openidx_app role.
func throwawayRolePool(t *testing.T, admin *pgxpool.Pool, probeDSN string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := fmt.Sprintf("rls_probe_%d", time.Now().UnixNano()%100000)
	pw := "probe_pw"
	_, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'", role, pw))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+role) })
	for _, g := range []string{
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT ON users TO " + role,
	} {
		_, err := admin.Exec(ctx, g)
		require.NoError(t, err)
	}
	u, err := url.Parse(probeDSN)
	require.NoError(t, err)
	u.User = url.UserPassword(role, pw)
	pool, err := pgxpool.New(ctx, u.String())
	require.NoError(t, err)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("probe role cannot connect (pg_hba?): %v", err)
	}
	return pool
}
```

- [ ] **Step 2: Run the test** (needs a reachable admin DB with CREATE DATABASE +
  CREATE ROLE privilege — the local `oidx-pg` superuser qualifies):

```bash
DATABASE_URL="postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable" \
  go test -tags=integration ./test/integration/ -run TestComposeMigrateSeedProducesRLSInstall -v
```
Expected: PASS. (Run against `oidx-pg` requires `dangerouslyDisableSandbox`.)

- [ ] **Step 3: Commit**

```bash
git add test/integration/compose_seed_test.go
git commit -m "test(compose): e2e — migrate-from-empty + seed.sql yields RLS-enforced install"
```

### Task 6: PR 1 — open PR, CI green, merge (with go-ahead)

- [ ] **Step 1:** `git push -u origin feat/compose-migrations-own-schema`
- [ ] **Step 2:** `gh pr create` — title `feat(compose): migrations own the schema + seed (PR 1/2)`;
  body summarizing the empirical findings, the retire of init-db.sql, and that the
  app still connects as superuser (RLS not yet enforced — PR2). Note verification =
  DB-level e2e + `compose config` (no full `compose up` in CI).
- [ ] **Step 3:** Adversarial review (independent subagent) + CI Required Checks green.
- [ ] **Step 4:** Merge on explicit per-PR go-ahead (branch-protected main).

---

# PR 2 — `openidx_app` cutover (RLS enforces)

> Branch from `main` after PR 1 merges: `git checkout main && git pull &&
> git checkout -b feat/compose-openidx-app-cutover`.

### Task 7: Password hook + postgres env

**Files:**
- Create: `deployments/docker/set-app-role-password.sh`
- Modify: `deployments/docker/docker-compose.yml`, `docker-compose.prod.yml`

- [ ] **Step 1: Create the hook** (mode 0755):

```sh
#!/bin/sh
# Sets the openidx_app role password at first cluster init. Mounted as a zz- initdb
# hook so it runs AFTER 00-bootstrap.sql created the (passwordless) role. Only runs
# on first init of a fresh volume; for an existing volume set it once via ALTER ROLE.
set -e
if [ -n "$OPENIDX_APP_PASSWORD" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER ROLE openidx_app WITH LOGIN PASSWORD '$OPENIDX_APP_PASSWORD';"
fi
```

- [ ] **Step 2: Mount the hook + add the env var to postgres** in both files:

```yaml
    environment:
      POSTGRES_DB: openidx
      POSTGRES_USER: openidx
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required - run scripts/generate-secrets.sh}
      OPENIDX_APP_PASSWORD: ${OPENIDX_APP_PASSWORD:?OPENIDX_APP_PASSWORD required - run scripts/generate-secrets.sh}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./bootstrap.sql:/docker-entrypoint-initdb.d/00-bootstrap.sql:ro
      - ./init-guacamole.sh:/docker-entrypoint-initdb.d/00-init-guacamole.sh:ro
      - ./init-guacamole.sql:/docker-entrypoint-initdb.d/guacamole-schema.sql:ro
      - ./set-app-role-password.sh:/docker-entrypoint-initdb.d/zz-set-app-role-password.sh:ro
```

- [ ] **Step 3: Commit** `git add -A && git commit -m "feat(compose): openidx_app password hook + postgres env"`

### Task 8: Cut the 8/7 app services to `openidx_app`

**Files:** `docker-compose.yml` (8 services), `docker-compose.prod.yml` (7)

- [ ] **Step 1:** In each app service's `DATABASE_URL`, replace
  `postgres://openidx:${POSTGRES_PASSWORD:?...}` with
  `postgres://openidx_app:${OPENIDX_APP_PASSWORD:?OPENIDX_APP_PASSWORD required - run scripts/generate-secrets.sh}`.
  Keep the `@postgres:5432/openidx?sslmode=${DATABASE_SSL_MODE:-disable}` tail.
  The `migrate` and `seed` services **keep the superuser** URL (they own DDL/seed).
  Any Keycloak/`KC_DB_*` (if present in prod) **stays superuser**.

```bash
# after editing, verify no app service still uses the superuser (only migrate+seed should):
grep -c 'DATABASE_URL=postgres://openidx:' deployments/docker/docker-compose.yml   # expect 2 (migrate, seed)
grep -c 'DATABASE_URL=postgres://openidx_app:' deployments/docker/docker-compose.yml # expect 8
```

- [ ] **Step 2: Validate** `docker compose config` for both files (as Task 3 Step 5).
- [ ] **Step 3: Commit** `git add -A && git commit -m "feat(compose): cut 8 app services to openidx_app (RLS enforces)"`

### Task 9: Env files

**Files:** `deployments/docker/.env`, `deployments/docker/.env.production`

- [ ] **Step 1:** Add to `.env` a real generated dev value:
  `OPENIDX_APP_PASSWORD=<generated 32+ char value>` (generate with
  `openssl rand -base64 24`; never reuse `POSTGRES_PASSWORD`).
- [ ] **Step 2:** Add to `.env.production`:
  `OPENIDX_APP_PASSWORD=CHANGE_THIS_GENERATE_SECURE_PASSWORD` (placeholder only —
  matches the `POSTGRES_PASSWORD` convention; never a real secret). Verify no
  `CHANGE_ME`/real-secret gitleaks trip.
- [ ] **Step 3: Commit** `git add -A && git commit -m "feat(compose): OPENIDX_APP_PASSWORD in .env / .env.production"`

### Task 10: PR 2 — open PR, CI green, merge (with go-ahead)

- [ ] Push, `gh pr create` (title `feat(compose): openidx_app cutover — RLS enforces (PR 2/2)`),
  adversarial review, CI green, merge on explicit go-ahead.
- [ ] Note in the PR body: existing-volume operators must set the `openidx_app`
  password once via `ALTER ROLE` (the initdb hook only fires on a fresh volume).

---

## Self-Review notes (checked against the spec)

- **Spec coverage:** bootstrap (Task 2), migrate service (Task 3), seed SQL+service
  (Tasks 1,3), role cutover (Task 8), password hook (Task 7), env (Task 9),
  DB-level e2e + `compose config` (Tasks 5,3) — all present. 2-PR split preserved
  (PR1 app-stays-superuser; PR2 cutover).
- **Open questions resolved:** parity tests → retire (Task 4); extensions → none
  needed (gen_random_uuid is PG16 core; bootstrap notes it); Guacamole init → kept
  as separate self-contained mounts (Task 3 keeps both).
- **Standing-rule guard:** the e2e test creates its OWN throwaway role, never
  `ALTER ROLE openidx_app` against the shared cluster (Task 5).
- **Ordering:** seed.sql is extracted from init-db (Task 1) BEFORE init-db is deleted
  (Task 4).
