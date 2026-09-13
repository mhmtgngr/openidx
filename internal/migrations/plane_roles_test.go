package migrations_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// THE CUTOVER, AGAINST THE WHOLE CHAIN.
//
// v189_plane_roles_test.go proves the three roles behave: they inherit the
// tenant belt, the server cancels a query that outruns its budget, and an idle
// transaction is closed out. It proves all of that against v53 and v189 alone,
// which is the right scope for a migration test and leaves one question open.
//
// The roles INHERIT their grants -- they hold none of their own. Whether that
// inheritance actually covers what the application touches is a property of
// the FULL chain, not of v189: two hundred-odd tables arrive across a hundred
// and ninety migrations, some granting to openidx_app explicitly and the rest
// relying on the default privileges v53 set. One table that got neither is a
// service that starts, passes its health check, and answers a single endpoint
// with "permission denied for table" -- the failure mode the chart's new
// database.planeRoles switch would otherwise ship.
//
// So this file applies every migration as a least-privileged owner, the way
// the deployment does, and then asks the database what each plane role can
// reach.

const planeCutoverProbePassword = "plane-cutover-not-a-credential"

// cutoverSuperuserDSN is the same gate v189_plane_roles_test.go uses, spelled
// again because that file is in package `migrations` and this one is in
// `migrations_test` -- it has to import the package to run the migrator, which
// the internal test file does not.
//
// A superuser is needed for the same reason the chart has a bootstrap hook:
// CREATE ROLE and CREATE DATABASE are exactly what the application's own role
// cannot do.
func cutoverSuperuserDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_SUPERUSER_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_SUPERUSER_DSN not set; the cutover needs CREATE ROLE and CREATE DATABASE")
	}
	return dsn
}

// cutoverQuoteLiteral is the same one-liner, for the same reason.
func cutoverQuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// planeRoleNames is the table v189 provisions, with the budgets it attaches, in
// milliseconds -- the unit pg_settings reports and the only spelling that
// cannot be argued with, since Postgres normalises '60s' into "1min" on the way
// in.
var planeRoleNames = []struct {
	name          string
	stmtTimeoutMS int64
	idleTimeoutMS int64
}{
	{"openidx_issue", 2_000, 60_000},
	{"openidx_admin", 10_000, 120_000},
	{"openidx_event", 30_000, 300_000},
}

// planeCutoverFixture is the deployment in miniature: a NOSUPERUSER
// NOCREATEROLE NOBYPASSRLS owner with its own database, the roles the chart's
// db-bootstrap hook pre-creates, and the whole migration chain applied by that
// owner.
type planeCutoverFixture struct {
	admin   *pgx.Conn
	dsn     string
	owner   *database.PostgresDB
	ownerDB string
}

// The SQL below is what templates/db-bootstrap-job.yaml runs. v189 guards every
// privileged statement with "is it already so?", so with the hook's work done
// its own copy only reads catalogue tables -- which is exactly the arrangement
// this fixture has to reproduce for the chain to apply at all.
const planeCutoverBootstrapSQL = `DO $$
DECLARE r record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  FOR r IN SELECT * FROM (VALUES
      ('openidx_issue', '2s',  '60s'),
      ('openidx_admin', '10s', '120s'),
      ('openidx_event', '30s', '300s')
    ) AS t(rolename, stmt_timeout, idle_timeout)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.rolename) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT IN ROLE openidx_app', r.rolename);
    END IF;
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r.rolename, r.stmt_timeout);
    EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', r.rolename, r.idle_timeout);
  END LOOP;
END $$;`

func newPlaneCutoverFixture(t *testing.T) *planeCutoverFixture {
	t.Helper()
	ctx := context.Background()
	dsn := cutoverSuperuserDSN(t)

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("connect as the superuser: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	const (
		ownerRole = "openidx_cutover_owner"
		ownerPass = "cutover-owner-not-a-credential"
		ownerDB   = "openidx_cutover_test"
	)
	for _, stmt := range []string{
		"DROP DATABASE IF EXISTS " + ownerDB,
		"DROP ROLE IF EXISTS " + ownerRole,
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS",
			ownerRole, cutoverQuoteLiteral(ownerPass)),
		fmt.Sprintf("CREATE DATABASE %s OWNER %s", ownerDB, ownerRole),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if _, err := admin.Exec(ctx, planeCutoverBootstrapSQL); err != nil {
		t.Fatalf("bootstrap the roles the hook pre-creates: %v", err)
	}

	owner, err := database.NewPostgres(planeCutoverDSN(t, dsn, ownerRole, ownerPass, ownerDB))
	if err != nil {
		t.Fatalf("connect as %s: %v", ownerRole, err)
	}

	// One cleanup, in an order that works: the pool first, then the database
	// (roles cannot be dropped while a database they can reach still refers to
	// them), then the roles.
	t.Cleanup(func() {
		bg := context.Background()
		_ = owner.Close()
		_, _ = admin.Exec(bg, "DROP DATABASE IF EXISTS "+ownerDB)
		for _, r := range planeRoleNames {
			_, _ = admin.Exec(bg, "DROP ROLE IF EXISTS "+r.name)
		}
		_, _ = admin.Exec(bg, "DROP ROLE IF EXISTS "+ownerRole)
	})

	if err := migrations.NewMigrator(owner.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("the chain must apply as a non-superuser owner: %v", err)
	}
	return &planeCutoverFixture{admin: admin, dsn: dsn, owner: owner, ownerDB: ownerDB}
}

// planeCutoverDSN rewrites the superuser DSN to name another role and database.
func planeCutoverDSN(t *testing.T, base, user, pass, dbname string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, pass, cfg.Host, cfg.Port, dbname)
}

// The cutover the design asks for is one sentence -- "point a service's
// DATABASE_URL at its plane role" -- and this runs it. A single missing grant
// is an outage on one endpoint of one service, behind a green rollout.
func TestV189PlaneRolesReachEveryTableAfterTheFullChain(t *testing.T) {
	f := newPlaneCutoverFixture(t)
	ctx := context.Background()

	var tables int
	if err := f.owner.Pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'public' AND c.relkind = 'r'`).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	// Vacuity guard: a chain that created nothing would make everything below
	// true for the wrong reason.
	if tables < 100 {
		t.Fatalf("only %d tables in public; the migration chain cannot have run", tables)
	}

	for _, r := range planeRoleNames {
		var missing []string
		rows, err := f.owner.Pool.Query(ctx, `
SELECT c.relname,
       has_table_privilege($1, c.oid, 'SELECT'),
       has_table_privilege($1, c.oid, 'INSERT'),
       has_table_privilege($1, c.oid, 'UPDATE'),
       has_table_privilege($1, c.oid, 'DELETE')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'r'
 ORDER BY c.relname`, r.name)
		if err != nil {
			t.Fatalf("%s: privilege sweep: %v", r.name, err)
		}
		for rows.Next() {
			var name string
			var sel, ins, upd, del bool
			if err := rows.Scan(&name, &sel, &ins, &upd, &del); err != nil {
				rows.Close()
				t.Fatalf("%s: scan: %v", r.name, err)
			}
			if !sel || !ins || !upd || !del {
				missing = append(missing, fmt.Sprintf("%s (select=%v insert=%v update=%v delete=%v)",
					name, sel, ins, upd, del))
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("%s: privilege sweep: %v", r.name, err)
		}
		if len(missing) > 0 {
			t.Errorf("%s cannot run the application on %d of %d table(s); pointing a service at it would fail at runtime:\n  %s",
				r.name, len(missing), tables, strings.Join(missing, "\n  "))
		}

		var seqGaps []string
		seqRows, err := f.owner.Pool.Query(ctx, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'S'
   AND NOT has_sequence_privilege($1, c.oid, 'USAGE')
 ORDER BY c.relname`, r.name)
		if err != nil {
			t.Fatalf("%s: sequence sweep: %v", r.name, err)
		}
		for seqRows.Next() {
			var name string
			if err := seqRows.Scan(&name); err != nil {
				seqRows.Close()
				t.Fatalf("%s: scan sequence: %v", r.name, err)
			}
			seqGaps = append(seqGaps, name)
		}
		seqRows.Close()
		if len(seqGaps) > 0 {
			t.Errorf("%s lacks USAGE on %d sequence(s); every INSERT into their tables would fail:\n  %s",
				r.name, len(seqGaps), strings.Join(seqGaps, "\n  "))
		}
	}
	if !t.Failed() {
		t.Logf("all three plane roles reach every one of %d tables and every sequence", tables)
	}
}

// The budget is attached to the ROLE, and the application does not connect with
// a bare pgx conn -- it connects with database.NewPostgres, which sets server
// runtime parameters of its own. DB_STATEMENT_TIMEOUT sets the very same
// parameter, and a runtime parameter BEATS the role's ALTER ROLE ... SET: a
// fleet-wide 30s would silently replace the ISSUE plane's 2s, on every service,
// with nothing in any log to say so. The chart refuses that combination; this
// is the other half, measured through the pool the services actually use.
func TestV189PlaneRoleBudgetsSurviveTheApplicationPool(t *testing.T) {
	f := newPlaneCutoverFixture(t)
	ctx := context.Background()

	const settingMS = `SELECT setting::bigint FROM pg_settings WHERE name = $1`
	for _, r := range planeRoleNames {
		if _, err := f.admin.Exec(ctx,
			fmt.Sprintf("ALTER ROLE %s PASSWORD %s", r.name, cutoverQuoteLiteral(planeCutoverProbePassword))); err != nil {
			t.Fatalf("set a login password on %s: %v", r.name, err)
		}
		pool, err := database.NewPostgres(planeCutoverDSN(t, f.dsn, r.name, planeCutoverProbePassword, f.ownerDB))
		if err != nil {
			t.Fatalf("connect as %s: %v", r.name, err)
		}

		var stmt, idle int64
		if err := pool.Pool.QueryRow(ctx, settingMS, "statement_timeout").Scan(&stmt); err != nil {
			_ = pool.Close()
			t.Fatalf("%s: read statement_timeout: %v", r.name, err)
		}
		if err := pool.Pool.QueryRow(ctx, settingMS, "idle_in_transaction_session_timeout").Scan(&idle); err != nil {
			_ = pool.Close()
			t.Fatalf("%s: read idle_in_transaction_session_timeout: %v", r.name, err)
		}
		_ = pool.Close()

		if stmt != r.stmtTimeoutMS {
			t.Errorf("%s reached the application pool with statement_timeout=%dms, want %dms", r.name, stmt, r.stmtTimeoutMS)
		}
		if idle != r.idleTimeoutMS {
			t.Errorf("%s reached the application pool with idle_in_transaction_session_timeout=%dms, want %dms", r.name, idle, r.idleTimeoutMS)
		}
		// Zero is "no limit", which is what every role has before v189 and what
		// an override would most likely produce.
		if stmt == 0 || idle == 0 {
			t.Errorf("%s has an unlimited budget through the application pool (statement=%dms idle=%dms)", r.name, stmt, idle)
		}
	}
}
