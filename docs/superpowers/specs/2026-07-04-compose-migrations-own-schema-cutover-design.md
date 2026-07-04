# Compose: migrations own the schema + `openidx_app` RLS cutover

> **Supersedes** `2026-06-30-p1-compose-openidx-app-cutover-design.md` (DEFERRED).
> That spec proposed *layering* migrations on top of `init-db.sql` and deferred on
> the `ziti_certificates`/v29 collision. This spec adopts the deferral note's
> "correct path" (migrations own the schema) and is grounded in fresh empirical
> findings (2026-07-04) that make the initiative much smaller than feared.

## Goal

Make a fresh `docker compose up` produce the **same RLS-enforced, `openidx_app`-scoped**
deployment the box already runs — so compose deployments are tenant-isolated, not
pre-multi-tenancy.

## Empirical findings (2026-07-04, against the dev Postgres)

Verified by creating throwaway DBs and running the real `cmd/migrate`:

1. **Layering is dead.** `init-db.sql` → `migrate up` still fails at **v29**
   (`CREATE INDEX … ON ziti_certificates(identity_id)` → `column "identity_id"
   does not exist`). The v54/v63 reconciles fixed *end-state* parity
   (`TestInitDBColumnParity` is directional, init-db ⊆ migrations) but **not** the
   temporal ordering: v29 references a column init-db's table lacks until v63.
2. **`init-db.sql` is itself broken** on current Postgres:
   `deployments/docker/init-db.sql:2528` creates a partial index with
   `WHERE … expires_at > NOW()` → `ERROR: functions in index predicate must be
   marked IMMUTABLE`. init-db only partially applies (113 tables).
3. **migrate-from-empty is clean and complete.** Empty DB → `migrate up` → exit 0,
   **v67**, 181 tables, `users.org_id`=true, `users.relforcerowsecurity`=true, and
   the `openidx_app` role exists (created by v53).
4. **Migrations already seed a working admin install.** Contrary to the old spec's
   "migrations only seed the default org," migrate-from-empty yields: default org,
   `admin` user (bcrypt hash), the **`admin-console` OAuth client**, 5 roles, 9
   permissions, `user_roles` giving admin the `admin` role, and `system_settings`.
5. **The only functional seed gap is `role_permissions` (0 after migrate vs 5 in
   init-db) — and it does not block admin.** Admin authority is granted **by role
   name** (`role == "admin" || role == "superadmin"` is checked across identity,
   MFA, risk, SCIM, etc.), and admin already holds the `admin` role. The init-db
   `role_permissions` rows only add granular RBAC for the *non-admin* roles
   (auditor/developer/manager/user). Remaining init-db extras are default policy
   rows (risk/posture/privacy/notification/lifecycle/ispm) + tenant branding +
   demo data (demo users, demo proxy routes, demo apps).

**Consequence:** we do **not** need to relocate all 39 init-db INSERTs. Migrations
already bootstrap login. The seed step only carries the *functional delta*
migrations don't provide (RBAC completeness + default policies), org-scoped and
idempotent. Demo/sample rows are intentionally dropped (documented).

## Architecture

Boot order (the invariant this guarantees):

```
postgres first-init
  → 00-bootstrap.sh / bootstrap.sql   (extensions + passwordless openidx_app role)
  → zz-set-app-role-password.sh       (ALTER ROLE openidx_app … PASSWORD, if env set)
postgres healthy
  → migrate service   (one-shot, superuser owner, `up`)   → full v1–v67 schema + RLS belt + login seed
  → seed service      (one-shot, superuser, SET app.bypass_rls) → role_permissions + default policies (delta only)
app services (×8)     (openidx_app, NOSUPERUSER)          → RLS enforces
```

Why the minimal bootstrap still creates the role: initdb hooks run **before** the
`migrate` service, so the `zz-` password hook needs `openidx_app` to already exist.
v53's `CREATE ROLE … IF NOT EXISTS` is then a no-op when migrate runs.

Why the seed runs as the superuser with `SET app.bypass_rls='on'`: after migrations
the RLS belt is FORCE'd; even the owner is subject to policy on scoped tables, so
the seed sets the bypass GUC to insert the default-org rows. (Superusers bypass RLS
anyway, but setting the GUC makes the seed correct regardless of the role it runs
as, and self-documents intent.)

## Components

### 1. Reduce `init-db.sql` → `deployments/docker/bootstrap.sql`
Replace the ~3.8k-line init-db table/seed dump with a minimal bootstrap:
- `CREATE EXTENSION IF NOT EXISTS` for the extensions migrations assume
  (`uuid-ossp`, `pgcrypto`, `citext`, … — enumerate from the current init-db head).
- `CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`
  wrapped in `IF NOT EXISTS` (verbatim from init-db's current role block).
- Nothing else — no tables, no seeds. This **moots the `NOW()` index bug**.

Keep the Guacamole init scripts (`init-guacamole.sh` / `.sql`) as-is — Guacamole
manages its own schema and is not an RLS/OpenIDX table set. *(Verify during
implementation that Guacamole's own tables don't depend on anything init-db.sql
used to create; they are self-contained per the current mount.)*

**`init-db.sql` is retired as the schema source.** `TestInitDBParity` /
`TestInitDBColumnParity` currently guard init-db against migrations. Since init-db
no longer defines tables, those tests must be repointed or retired — see Open
questions. This is the one place the change ripples into Go tests.

### 2. `migrate` one-shot service (both compose files)
- `build`: `context: ../..`, `dockerfile: deployments/docker/Dockerfile.service`,
  `args: { SERVICE_NAME: migrate }` (that Dockerfile builds `./cmd/${SERVICE_NAME}`
  → `/app/migrate`).
- `command: ["up"]`.
- `DATABASE_URL` = **superuser** `openidx:${POSTGRES_PASSWORD}@postgres:5432/openidx?sslmode=${DATABASE_SSL_MODE:-disable}` (owns DDL/RLS).
- `depends_on: { postgres: { condition: service_healthy } }`; `restart: "no"`.

### 3. `seed` one-shot service (both compose files)
- Reuse the postgres image (has `psql`) or `Dockerfile.service`; run
  `psql … -f /seed/seed.sql`. Mount `./seed.sql:/seed/seed.sql:ro`.
- `DATABASE_URL`/PG env = **superuser**.
- `depends_on: { migrate: { condition: service_completed_successfully } }`;
  `restart: "no"`.

**`deployments/docker/seed.sql`** — the functional delta only, all idempotent
(`ON CONFLICT DO NOTHING`), all default-org-scoped, guarded by `SET app.bypass_rls='on';`:
- `role_permissions` — the 5 init-db mappings (admin→all; auditor/developer/manager/user→subset).
- Default policy/config rows migrations omit: `risk_policies`, `posture_check_types`,
  `privacy_retention_policies`, `notification_routing_rules`, `lifecycle_policies`,
  `ispm_rules`, `tenant_branding` — copied from init-db, adding `org_id =
  '00000000-0000-0000-0000-000000000010'` (the default org v25/v35 seed).
- **Excluded (documented in a header comment):** demo users (jsmith/jdoe/bwilson),
  demo `proxy_routes`, demo `applications`, `ziti_user_sync` demo row — sample data,
  not required for a functional install; keeping them would need org_id rework for no
  operational value.

### 4. App services cut over to `openidx_app` (both compose files)
- The 8 OpenIDX services' `DATABASE_URL` →
  `openidx_app:${OPENIDX_APP_PASSWORD:?OPENIDX_APP_PASSWORD required}@postgres:5432/openidx?sslmode=${DATABASE_SSL_MODE:-disable}`.
- Add `depends_on: { seed: { condition: service_completed_successfully } }`
  (transitively after migrate) alongside existing postgres/redis deps.
- **Keycloak `KC_DB_*` stays on the superuser** — not an OpenIDX/RLS service.
- The P0-2 pre-resolution bypass fix is already on `main`, so the non-owner role is
  safe for the data plane (proxy route/api-key/device lookups use `WithBypassRLS`).

### 5. `openidx_app` password provisioning
- `deployments/docker/set-app-role-password.sh` mounted as
  `/docker-entrypoint-initdb.d/zz-set-app-role-password.sh` (the `zz-` prefix sorts
  after `00-bootstrap`, so the role exists):
  ```sh
  #!/bin/sh
  set -e
  if [ -n "$OPENIDX_APP_PASSWORD" ]; then
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
      -c "ALTER ROLE openidx_app WITH LOGIN PASSWORD '$OPENIDX_APP_PASSWORD';"
  fi
  ```
- Add `OPENIDX_APP_PASSWORD` to the postgres service `environment` in both files.
- Initdb hooks run only on **first** cluster init; for an existing volume the
  operator sets it once via `ALTER ROLE` — documented in `.env`.

### 6. Env files
- `deployments/docker/.env` — real generated `OPENIDX_APP_PASSWORD` for dev.
- `deployments/docker/.env.production` — `CHANGE_THIS_GENERATE_SECURE_PASSWORD`
  placeholder (matching the `POSTGRES_PASSWORD` convention). Never a real secret.

## Decomposition — 2 independently-working PRs

- **PR 1 — schema via migrations + seed (app stays superuser).**
  bootstrap.sql, `migrate` service, `seed` service + `seed.sql`, parity-test
  repoint. Result: fresh compose up builds a migration-owned, seeded, login-capable
  stack and **fixes the broken init-db**. RLS policies exist but don't yet bite
  (app still superuser → bypasses RLS; no worse than today). Independently shippable.
- **PR 2 — `openidx_app` cutover (RLS enforces).**
  App DSN → `openidx_app`, password hook, env vars, `depends_on seed`. Result:
  compose is tenant-isolated. Small, and the actual security win.

## Testing / verification (chosen: DB-level e2e + `compose config`)

- **DB-level e2e (authoritative for mechanics), added as a Go integration test**
  (`test/integration`, DB-backed, mirrors existing `cross_org_test` helpers):
  1. throwaway DB → `cmd/migrate up` → apply `seed.sql`.
  2. Assert `users.org_id` exists and `relforcerowsecurity=true` on a scoped table.
  3. Assert login bootstrap present: `admin` user w/ hash, `admin-console` client,
     admin holds `admin` role, `role_permissions` populated after seed.
  4. Assert RLS bites as `openidx_app`: a no-GUC query on a scoped table → 0 rows;
     a `WithBypassRLS` query → rows. *(Set the role password to a throwaway value in
     the test DB only — never `ALTER ROLE … PASSWORD` against the shared cluster's
     app role per the standing rule; use a distinct throwaway role or the GUC-only
     assertion if role-password setup would touch the shared role.)*
- **`docker compose config`** on both files: validates YAML, the `migrate`/`seed`
  services, `depends_on` conditions, and env interpolation.
- **No full `docker compose up` in CI** — heavy, and the box runs systemd not
  compose. Called out explicitly; the e2e + `compose config` cover the mechanics.
- `go build ./...`, `go vet`, `gofmt`, golangci-lint, `TestInitDBParity`/
  `TestInitDBColumnParity` (repointed), CI Required Checks green before each merge.

## Out of scope (deliberate)

- Prod `sslmode=require` default — separate hardening backlog item (this spec keeps
  the existing `${DATABASE_SSL_MODE:-disable}` interpolation untouched).
- The missing `scripts/generate-secrets.sh` referenced by the `:?` hints — note only.
- Managed/RDS/Helm deploys already run their own migration runners — unchanged.
- Demo/sample seed data — intentionally not carried over (documented in seed.sql).

## Open questions (resolve during PR 1 implementation, not blocking the design)

1. **Parity tests:** with init-db.sql retired as the schema source,
   `TestInitDBParity`/`TestInitDBColumnParity` lose their subject. Options: (a) delete
   them (migrations are now the sole source — the drift class they guarded no longer
   exists); (b) repoint them to assert bootstrap.sql only creates the role/extensions.
   Lean (a) with a clear commit message, since the whole point is "one schema source."
2. **Extension list:** enumerate exactly which `CREATE EXTENSION`s migrations assume
   (grep migrations for `uuid_generate`, `gen_random_uuid`, `citext`, `pgcrypto`) so
   bootstrap.sql provides them before migrate runs.
3. **Guacamole init:** confirm `init-guacamole.*` is fully self-contained once
   init-db's tables are gone (it appeared independent in the mount list).
