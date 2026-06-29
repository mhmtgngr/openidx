# v1.8 RLS enforcement — activate tenant isolation via a non-owner runtime role

## Context

The v1.8 Row-Level Security belt is **already built and applied** — it is simply
inert. Migration v37 (`rls_activate`) rewrote the 68 `pol_<t>_org_scope` policies
from `USING (true)` to the real tenant predicate

```
current_setting('app.bypass_rls', true) = 'on'
  OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
```

and ran `ENABLE` + `FORCE ROW LEVEL SECURITY` on every scoped table. The
per-request GUCs (`app.org_id`, `app.bypass_rls`) are set at pgxpool checkout
from `orgctx` (`internal/common/database/rls.go`), and background/cross-org work
opts into the bypass via `orgctx.WithBypassRLS`.

Verified live: `users` is `relrowsecurity=true, relforcerowsecurity=true` with
the restrictive policy — yet a no-GUC `SELECT count(*) FROM users` returns **all
11 rows across orgs**, because the app connects as `openidx`, which is
`rolsuper=t, rolbypassrls=t`. **Superuser / BYPASSRLS roles bypass RLS entirely,
regardless of FORCE.** So nothing the policies say takes effect.

**This slice does exactly one thing: run the application under a non-superuser,
non-BYPASSRLS, non-owner Postgres role so the existing policies bite.** No policy
predicate changes. The bypass path for the Relations Doctor, the continuous
verifier, and migrations already works through `app.bypass_rls` in the policy
predicate, independent of the role.

### Settled decisions

- **Role model:** a dedicated **non-owner runtime role** (`openidx_app`,
  `NOSUPERUSER NOBYPASSRLS`) with DML grants but no table ownership. Non-owners
  are subject to RLS automatically. Tables stay owned by `openidx`, which runs
  DDL/migrations. (Not the owner+FORCE single-role variant.)
- **Scope:** full activation, phased and verified — provision → cut over the live
  box → verify RLS bites — in one slice, reversible by reverting `DATABASE_URL`.
- **Grants:** blanket `GRANT … ON ALL TABLES` + `ALTER DEFAULT PRIVILEGES`, so
  grant-completeness holds by construction (no per-service enumeration).
- **Password:** the migration creates the role **passwordless**; the password is
  set out-of-band at deploy time so no secret lands in git.

### Constraint that shapes the design

`identity-service` calls `migrations.MustAutoMigrate` on boot **when
`AUTO_MIGRATE` is on** (it is **off** on this box). A non-owner runtime role
cannot run DDL, so the split requires: **services keep `AUTO_MIGRATE` off and
migrations run via the standalone `cmd/migrate` (`openidx migrate up`) under the
owner role.** This is already the box's posture; the spec makes it a documented
requirement.

## Design

### Component 1 — Migration v53: provision the runtime role

A new migration (`internal/migrations/sql_v53.go` + loader registration, next
free version after v52). Runs as the owner (`openidx`), so it may create roles
and grant. Idempotent.

**Up:**
```sql
-- Create the non-privileged runtime role (passwordless; password set at deploy).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT CONNECT ON DATABASE openidx TO openidx_app;
GRANT USAGE ON SCHEMA public TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO openidx_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO openidx_app;
-- Future migrations' objects (created by the owner) auto-grant to the runtime role.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO openidx_app;
```
(`GRANT CONNECT ON DATABASE openidx` hardcodes the DB name `openidx`, matching
the rest of the deployment; adjust if the DB name differs.)

**Down:** revoke and drop (idempotent; the role owns nothing):
```sql
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM openidx_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM openidx_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM openidx_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM openidx_app;
REVOKE ALL ON SCHEMA public FROM openidx_app;
REVOKE ALL ON DATABASE openidx FROM openidx_app;
DROP ROLE IF EXISTS openidx_app;
```

Why blanket grants: every scoped table already exists at v53 time; `ON ALL
TABLES` covers all of them, and `ALTER DEFAULT PRIVILEGES` covers any added
later — so no service can hit a missing-grant error on a table it legitimately
uses. (RLS still restricts *rows*; grants only gate *table access*.)

### Component 2 — `init-db.sql` parity

Append the same role creation + grants + default privileges to
`deployments/docker/init-db.sql` (the init superuser runs it), so a fresh
install has `openidx_app`. The apisix-edge runbook notes setting its password
(`ALTER ROLE openidx_app PASSWORD …`) and pointing the app `DATABASE_URL` at it.

### Component 3 — Cutover (the box)

1. Set the role's password: `ALTER ROLE openidx_app PASSWORD '<generated>'`.
2. Point the **application** connection at it:
   - `~/.config/oidx/common.env`: `DATABASE_URL=postgres://openidx_app:<pw>@localhost:55432/openidx?sslmode=disable`
   - `~/oidx-runtime/run-access.sh`: same `DATABASE_URL` export (access uses the wrapper).
3. Leave the **migration** path on the owner: `cmd/migrate` / `openidx migrate up`
   continues to use the `openidx` DSN (DDL). Services keep `AUTO_MIGRATE` off.
4. Restart all 8 services.

### Component 4 — Live verification

As `openidx_app` (proves RLS now bites):
```
-- no GUC → policy predicate is false → 0 rows
SELECT count(*) FROM users;                          -- expect 0
-- scoped to an org → only that org's rows
SET app.org_id = '<org-uuid>'; SELECT count(*) FROM users;   -- expect that org's count
-- bypass (platform/Doctor/migration path) → all rows
SET app.org_id = ''; SET app.bypass_rls = 'on'; SELECT count(*) FROM users;  -- expect all
```
Then, end-to-end:
- Restart the 8 services on `openidx_app`; confirm each `/health` = 200.
- Exercise one representative read **and** write per service (e.g. list + create)
  to confirm the blanket grants are complete at runtime.
- Confirm the Relations & Integrity Doctor (`GET …/access/health/relations`) and
  the continuous verifier still function — both set `app.bypass_rls` via
  `orgctx.WithBypassRLS`, so they must see cross-org data as before.

## Risk & rollback

Highest-blast-radius change of the epic — it swaps the DB role for every service.
Mitigations:
- **Rollback is instant:** revert `DATABASE_URL` → `openidx` and restart. The
  role + grants are harmless to leave in place.
- **The smoke-test gate is mandatory** before declaring success — a missing grant
  or an unscoped query path surfaces as a runtime error or unexpectedly-empty
  result, caught by the per-service read/write checks.
- A query that relied on implicit cross-org visibility (and is *not* marked
  bypass) will now correctly return only the request's org — that is the intended
  behavior, but watch the smoke tests for any path that silently depended on
  seeing all orgs and isn't a legitimate platform/bypass path.

## Out of scope

- Any change to the RLS policy predicates or the `FORCE`/`ENABLE` state (v37 is
  correct and applied).
- Per-table or per-service grant tuning (blanket grant is intentional).
- CI / docker-compose role wiring beyond `init-db.sql` parity.
- Migrating the `cmd/migrate` runner or `AUTO_MIGRATE` semantics (the owner role
  keeps DDL; the spec only documents the requirement).

## Verification checklist

- `go build ./...`, `go vet ./internal/migrations/...` clean; migration v53
  registers and parses; `go test ./internal/migrations/` green.
- Live: migration v53 applied (owner); `openidx_app` exists `NOSUPERUSER
  NOBYPASSRLS`; as `openidx_app` a no-GUC scoped query returns 0, an org-scoped
  query returns that org, bypass returns all; all 8 services healthy on the new
  role with reads+writes working; Doctor + continuous-verify still work.
