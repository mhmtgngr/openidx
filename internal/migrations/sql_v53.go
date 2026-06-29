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
