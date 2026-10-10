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

-- The bypass role (issue #964): background work reads across tenants as this
-- role, which has the BYPASSRLS attribute, instead of setting a session GUC
-- on openidx_app that any session could set. IN ROLE openidx_app carries the
-- grants; BYPASSRLS is the role's own attribute and is what makes the
-- policies not apply to it. Passwordless like openidx_app: the password is
-- set by set-app-role-password.sh (OPENIDX_BYPASS_PASSWORD).
DO
$$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_bypass') THEN
    CREATE ROLE openidx_bypass LOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE INHERIT IN ROLE openidx_app;
  ELSIF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_bypass' AND rolbypassrls) THEN
    ALTER ROLE openidx_bypass BYPASSRLS;
  END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO openidx_bypass', current_database());
  -- The owner runs migrations and seeds. It can already disable row-level
  -- security on the tables it owns, so BYPASSRLS adds no power; it lets
  -- migration 231 remove the GUC clause the migrator relied on.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx' AND NOT rolbypassrls AND NOT rolsuper) THEN
    ALTER ROLE openidx BYPASSRLS;
  END IF;
END
$$;
