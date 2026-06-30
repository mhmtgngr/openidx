# P1 — Compose: run migrations + cut the app role over to `openidx_app`

> **STATUS: DEFERRED (2026-06-30).** Implementation was attempted and revealed
> this is the larger "collapse to one schema source" initiative (audit root-cause
> #1), not a single P1. Findings that block the "layer migrations on top of
> init-db" approach this spec proposed:
>
> 1. **init-db.sql's table DDL diverges from the migrations.** `migrate up` on an
>    init-db-bootstrapped DB fails at **v29 (`ziti_certificates`: index references
>    `identity_id`, which init-db's version of the table lacks)** — same class as
>    the `lifecycle_executions` collision. Reconciling each divergent table is
>    unbounded.
> 2. **`migrate up` on an EMPTY DB is clean** (v1–v55, `users.org_id` + FORCE RLS,
>    168 tables, and v53 even creates `openidx_app`). So migrations are a complete,
>    self-consistent schema source — the right model is "migrations own the
>    schema," not "layer on top."
> 3. **But init-db.sql carries 39 seed INSERTs migrations don't** (default admin
>    user, `admin-console` OAuth client, roles, permissions, `system_settings`,
>    demo apps). Dropping init-db's tables would drop that seed → a fresh
>    `docker compose up` would have no login/clients. Migrations only seed the
>    default org row.
>
> **Correct path for the dedicated initiative:** reduce init-db.sql to a minimal
> bootstrap (extensions + the passwordless `openidx_app` role, so the password
> hook still works at init time), relocate the 39 seeds into a post-migrate seed
> step compatible with the migrated schema, keep the migrate service + role
> cutover + password hook described below (built and `docker compose config`-
> validated in the deferred attempt), and verify with a full `docker compose up`.
> The plumbing design below is sound and reusable; the schema/seed reduction is
> the remaining work.



## Context

On the box, the app connects as the non-owner `openidx_app` role so the v37 RLS
policies enforce (P0-2 made that safe by bypass-wrapping pre-resolution
lookups). The **docker-compose stack never got this**, and the gap is deeper than
the role:

- **Compose has no migration runner / no `AUTO_MIGRATE`.** The schema comes
  entirely from `deployments/docker/init-db.sql` (mounted into
  `/docker-entrypoint-initdb.d/`).
- **`init-db.sql` has no multi-tenancy/RLS belt.** Its core scoped tables
  (`users`, `applications`, `proxy_routes`, `oauth_clients`, `audit_events`,
  `sessions`, …) have **no `org_id` column**, and there are **no `FORCE`/`ENABLE
  ROW LEVEL SECURITY` statements and no org-scope policies** — the entire v34–v37
  belt lives only in `internal/migrations`.
- All app services connect as the **`openidx` superuser**
  (`DATABASE_URL=postgres://openidx:${POSTGRES_PASSWORD}@postgres…`).

So a fresh `docker compose up` is pre-multi-tenancy at the schema level. Flipping
the DB URL to `openidx_app` alone would change the role but enforce nothing
(no policies/columns exist). The fix must make migrations run in compose.

## Approach (audit root-cause fix #1, minimal increment)

Keep `init-db.sql` and **layer migrations on top of it**: every migration's DDL
is `IF NOT EXISTS`/idempotent, so `cmd/migrate up` against an init-db-bootstrapped
DB adds the org_id columns (v34), backfill (v35), constraints (v36), the RLS belt
(v37), and the v38–v55 reconciles — leaving the schema fully migrated with RLS
forced. This is exactly how the box reached its current state, so it is proven.
App services then connect as `openidx_app`.

Fully reducing `init-db.sql` to extensions/roles/seed (the audit's end-state) is
a larger follow-up and is **out of scope** here — not needed to enforce RLS now.

### Changes (in `docker-compose.yml` and `docker-compose.prod.yml`)

**1. A one-shot `migrate` service.**
- `build`: `context: ../..`, `dockerfile: deployments/docker/Dockerfile.service`,
  `args: SERVICE_NAME=migrate` (that Dockerfile builds `./cmd/${SERVICE_NAME}`;
  runtime entrypoint is `/app/service`).
- `command: ["up"]` → runs `migrate up`.
- `DATABASE_URL` as the **`openidx` superuser** (owns DDL/RLS):
  `postgres://openidx:${POSTGRES_PASSWORD}@postgres:5432/openidx?sslmode=…`.
- `depends_on: { postgres: { condition: service_healthy } }`.
- `restart: "no"`; on the same `openidx-network`. (Its health endpoint is
  irrelevant — it exits 0; downstream gates on `service_completed_successfully`,
  not health.)

**2. App services cut over** — the 8 OpenIDX services (identity, governance,
provisioning, audit, admin-api, gateway, oauth, access; in `docker-compose.yml`
the access-service block too):
- `DATABASE_URL` → `postgres://openidx_app:${OPENIDX_APP_PASSWORD:?OPENIDX_APP_PASSWORD required}@postgres:5432/openidx?sslmode=…`.
- Add `depends_on: { migrate: { condition: service_completed_successfully } }`
  (alongside their existing postgres/redis deps) so they start only after
  migrations finish.
- **Keycloak's `KC_DB_*` stays on the superuser** — it is not an OpenIDX/RLS
  service and manages its own schema.

**3. Provision the `openidx_app` password.** The role is created passwordless by
`init-db.sql` (and idempotently by migration v53). Add a new
`deployments/docker/set-app-role-password.sh` mounted into the postgres service
as `/docker-entrypoint-initdb.d/zz-set-app-role-password.sh` (the `zz-` prefix
sorts **after** `init-db.sql`, so the role already exists). It runs:

```sh
#!/bin/sh
set -e
if [ -n "$OPENIDX_APP_PASSWORD" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER ROLE openidx_app WITH LOGIN PASSWORD '$OPENIDX_APP_PASSWORD';"
fi
```

Add `OPENIDX_APP_PASSWORD` to the postgres service `environment` in both files so
the hook can read it. (Initdb hooks only run on **first** cluster init; for an
existing volume the operator sets the password once via `ALTER ROLE` — documented
in `.env`.)

**4. Env files.** Add `OPENIDX_APP_PASSWORD` to `deployments/docker/.env` (a real
generated value for dev) and `deployments/docker/.env.production`
(`CHANGE_THIS_GENERATE_SECURE_PASSWORD` placeholder, matching the
`POSTGRES_PASSWORD` convention). No `.env.example` exists.

### Boot order (the invariant this design guarantees)

`postgres` first-init runs `init-db.sql` (tables + `openidx_app` role) then the
`zz-` hook (sets the role password) → postgres healthy → `migrate up` runs as the
superuser, layering org_id + RLS belt + reconciles → app services start as
`openidx_app` → RLS enforces (the P0-2 bypass fix, already on `main`, keeps
pre-resolution lookups working under the non-owner role).

## Out of scope (deliberate)

- Reducing `init-db.sql` to non-table bootstrap (extensions/roles/seed) — larger
  follow-up; migrations layering on top is sufficient now.
- Prod `sslmode=disable` hardcode in `docker-compose.prod.yml` — separate P1
  (`ValidateProduction` sslmode drift). Noted, not fixed here.
- The missing `scripts/generate-secrets.sh` (referenced by the `:?` hints but
  absent) — note; the operator generates secrets manually.
- Non-compose managed/RDS/Helm deploys already run migrations (their own runner);
  unchanged.

## Testing / verification

- **DB-level e2e (authoritative for the mechanics)**: against the dev Postgres,
  create a throwaway DB, apply `init-db.sql`, then run `cmd/migrate up`; assert
  `users` has `org_id` and `relforcerowsecurity = true`, and that `openidx_app`
  (with a password set) connects and a no-GUC query on a scoped table returns 0
  rows (RLS fail-closed) while a bypass query sees rows. This proves
  "migrations-on-top-of-init-db → RLS enforces as `openidx_app`."
- **`docker compose config`** on both files validates the YAML, the `migrate`
  service, the `depends_on` conditions, and env interpolation.
- Full `docker compose up` is heavy and the box runs systemd (not compose), so it
  is **not** part of automated verification; the DB-level e2e + `compose config`
  cover the mechanics and wiring. Called out explicitly.
- `go build ./...` (the migrate binary already builds); no Go changes expected.

## Verification checklist

- [ ] `migrate` service added to both compose files (superuser URL, `up`,
  `depends_on postgres healthy`, `restart: no`).
- [ ] 8 app services use `openidx_app:${OPENIDX_APP_PASSWORD}` and
  `depends_on migrate: service_completed_successfully`; Keycloak unchanged.
- [ ] `set-app-role-password.sh` created + mounted as `zz-…` in both files'
  postgres; `OPENIDX_APP_PASSWORD` in postgres env.
- [ ] `OPENIDX_APP_PASSWORD` added to `.env` and `.env.production`.
- [ ] DB-level e2e passes (org_id + FORCE RLS after migrate; `openidx_app`
  fail-closed without GUC); `docker compose config` valid for both files.
