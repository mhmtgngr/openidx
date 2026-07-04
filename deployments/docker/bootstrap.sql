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
