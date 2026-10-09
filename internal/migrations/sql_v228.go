package migrations

// Migration 228: the GUC leaves the policies.
//
// Every row-level-security policy let a session through when
// current_setting('app.bypass_rls') was 'on'. That setting is one any session
// may set, so a SQL injection on the application role could read every
// tenant (issue #964). Bypass-marked work now runs as a separate role with the
// BYPASSRLS attribute (internal/common/database/bypass.go); for that role
// the policies do not apply at all, and the clause is a hole with no use.
//
// This migration removes the clause from every policy, and it does so only
// when the deployment has finished moving: the bypass role exists, and the
// role running this migration can itself bypass RLS (the bootstrap gave the
// owner BYPASSRLS, or it is a superuser). Until then the clause is what lets
// background work and the migrator see all rows, and removing it would make
// every sweep see nothing. An install that has not bootstrapped the role gets
// a NOTICE and no change; production refuses to start without the role, so
// nobody runs there for long.
//
// The rewrite is textual on pg_get_expr's output, and it verifies itself: a
// policy that still mentions app.bypass_rls afterwards fails the migration,
// so an unusual policy is found here rather than left open.
//
// Down puts the clause back on every policy that scopes by app.org_id.
var bypassGUCLeavesPoliciesUp = `-- Migration 228: the bypass GUC leaves the policies.
DO
$$
DECLARE
  r record;
  can_bypass boolean;
  n int := 0;
  pat_lead text := '\(current_setting\(''app\.bypass_rls''::text, true\) = ''on''::text\) OR ';
  pat_trail text := ' OR \(current_setting\(''app\.bypass_rls''::text, true\) = ''on''::text\)';
  new_qual text;
  new_check text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_bypass') THEN
    RAISE NOTICE 'openidx_bypass does not exist: policies keep the app.bypass_rls clause. Bootstrap the role (deployments/docker/bootstrap.sql) and set DATABASE_BYPASS_URL.';
    RETURN;
  END IF;
  SELECT rolbypassrls OR rolsuper INTO can_bypass FROM pg_roles WHERE rolname = current_user;
  IF NOT can_bypass THEN
    RAISE NOTICE 'the migrating role % cannot bypass RLS: policies keep the app.bypass_rls clause. Give the owner BYPASSRLS as the bootstrap does.', current_user;
    RETURN;
  END IF;
  FOR r IN
    SELECT schemaname, tablename, policyname, qual, with_check
      FROM pg_policies
     WHERE schemaname = 'public'
       AND (qual LIKE '%app.bypass_rls%' OR with_check LIKE '%app.bypass_rls%')
  LOOP
    new_qual := regexp_replace(regexp_replace(r.qual, pat_lead, ''), pat_trail, '');
    new_check := regexp_replace(regexp_replace(r.with_check, pat_lead, ''), pat_trail, '');
    IF r.with_check IS NULL THEN
      EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s)', r.policyname, r.schemaname, r.tablename, new_qual);
    ELSE
      EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s) WITH CHECK (%s)', r.policyname, r.schemaname, r.tablename, new_qual, new_check);
    END IF;
    n := n + 1;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_policies
              WHERE schemaname = 'public'
                AND (qual LIKE '%app.bypass_rls%' OR with_check LIKE '%app.bypass_rls%')) THEN
    RAISE EXCEPTION 'a policy still mentions app.bypass_rls after the rewrite: % ',
      (SELECT string_agg(tablename || '.' || policyname, ', ') FROM pg_policies
        WHERE schemaname = 'public'
          AND (qual LIKE '%app.bypass_rls%' OR with_check LIKE '%app.bypass_rls%'));
  END IF;
  RAISE NOTICE 'migration 228: removed the app.bypass_rls clause from % policies', n;
END
$$;
`

var bypassGUCLeavesPoliciesDown = `-- Migration 228 down: the bypass GUC is a way through the policies again.
DO
$$
DECLARE
  r record;
  clause text := '(current_setting(''app.bypass_rls''::text, true) = ''on''::text) OR ';
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname, qual, with_check
      FROM pg_policies
     WHERE schemaname = 'public'
       AND qual LIKE '%app.org_id%'
       AND qual NOT LIKE '%app.bypass_rls%'
  LOOP
    IF r.with_check IS NULL THEN
      EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s)', r.policyname, r.schemaname, r.tablename, clause || r.qual);
    ELSE
      EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s) WITH CHECK (%s)', r.policyname, r.schemaname, r.tablename, clause || r.qual, clause || r.with_check);
    END IF;
  END LOOP;
END
$$;
`
