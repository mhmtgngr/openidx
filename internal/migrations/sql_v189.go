package migrations

// Migration v189 — one Postgres login role per availability plane, each with a
// statement timeout the plane can actually live with.
//
// THE PROBLEM. Every service connects as openidx_app (v53) with no query time
// limit, so one expensive query holds a backend for as long as it likes. That
// is fine until the day it is not: an audit search over a large table, a
// governance report, a SCIM bulk page with a bad predicate. Those are ADMIN and
// EVENT work, and while they run they are indistinguishable to Postgres from
// the login path -- same role, same pool budget, same priority. The design's
// whole premise (docs/architecture/2026-09-13-global-scale-cell-architecture-
// and-ddos.md §4.1) is that the expensive planes must be sheddable WITHOUT the
// cheap one noticing, and "the database cancels it" is the only layer that can
// enforce that once a query is already running. An application timeout does not
// help: cancelling the context abandons the Go call, while the backend keeps
// burning the CPU and holding the row locks.
//
// WHY ROLES AND NOT A DSN PARAMETER. statement_timeout can be set per
// connection (`options=-c statement_timeout=2000`), and that would be a smaller
// change -- but it lives in the DSN, which means it is one copy-paste away from
// being wrong in a values file nobody diffs, and there is no way to ask the
// database what a given service is allowed to do. Attached to a role it is a
// property of the SERVER: `\drds` lists it, an operator cannot lose it by
// editing a secret, and the same grant is in force for a psql session someone
// opens as that role at 3am.
//
// THE INHERITANCE IS THE SAFETY. Each role is created IN ROLE openidx_app, so
// it inherits openidx_app's DML grants AND -- the part that matters -- the v37
// FORCE RLS policies, which are granted TO openidx_app and apply to every role
// that has its privileges. A plane role is therefore exactly as tenant-scoped
// as openidx_app is; it can only be LESS capable, never more. NOBYPASSRLS is
// spelled out on each one anyway, because a role that quietly bypassed the belt
// would not fail, it would return every tenant's rows.
//
// THE NUMBERS are the design's (§4.1, §5.5): ISSUE 2s, ADMIN 10s, EVENT 30s.
// VERIFY gets no role because the design gives it no database at all.
//
// idle_in_transaction_session_timeout is set alongside, which the plan did not
// ask for. Without it the statement timeout is trivially bypassable: BEGIN, run
// a fast query, and hold the transaction open forever -- the backend stays
// pinned, its locks stay held, and vacuum cannot pass the oldest snapshot. The
// values are deliberately much looser than the statement timeouts (a minute to
// five) so they only ever catch work that is genuinely stuck, never a
// transaction that is merely doing something.
//
// PASSWORDLESS, like v53, and NOTHING USES THEM YET. The roles exist; a
// deployment opts in by pointing a service's DATABASE_URL at one. Until it
// does, this migration changes no behaviour whatsoever.
var planeRolesUp = `-- Migration 189: per-plane login roles with bounded query time.
DO
$$
DECLARE
  -- role, statement_timeout, idle_in_transaction_session_timeout
  r record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    RAISE EXCEPTION 'openidx_app is missing; migration v53 must run before v189';
  END IF;

  FOR r IN
    SELECT * FROM (VALUES
      ('openidx_issue', '2s',  '60s'),
      ('openidx_admin', '10s', '120s'),
      ('openidx_event', '30s', '300s')
    ) AS t(rolename, stmt_timeout, idle_timeout)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.rolename) THEN
      -- IN ROLE openidx_app: inherits its grants and, with them, the v37 RLS
      -- policies. NOINHERIT would silently detach both.
      EXECUTE format(
        'CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT IN ROLE openidx_app',
        r.rolename);
    ELSE
      -- Idempotent: an existing role is brought to the same attributes rather
      -- than left in whatever state a previous hand-edit put it in.
      EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT', r.rolename);
      EXECUTE format('GRANT openidx_app TO %I', r.rolename);
    END IF;

    -- Cluster-wide for the role rather than IN DATABASE: these roles connect to
    -- one database, and the unqualified form needs no database name (which CI
    -- and test databases do not share).
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r.rolename, r.stmt_timeout);
    EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', r.rolename, r.idle_timeout);
  END LOOP;
END
$$;
`

// Down drops the three roles. They own nothing and are granted nothing
// directly -- every privilege they have comes through openidx_app -- so the
// drop needs no REVOKE sweep, unlike v53. Guarded so it is a no-op when the
// roles were never provisioned.
//
// A role that is still someone's login will take the deployment with it, which
// is the correct direction: a down-migration that left a service connecting as
// a role with no timeout would undo the belt silently.
var planeRolesDown = `-- Migration 189 down: drop the per-plane login roles (no-op if absent).
DO
$$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['openidx_issue', 'openidx_admin', 'openidx_event']
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE openidx_app FROM %I', r);
      EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP;
END
$$;
`
