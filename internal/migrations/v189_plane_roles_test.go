package migrations

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The same dollar-quote guard v53 carries: v189's DO blocks must survive
// splitSQL as single statements. This one has a FOR loop and a FOREACH, so it
// has more inner semicolons to be shredded at than v53 did.
func TestV189SplitsCleanly(t *testing.T) {
	m := &Migrator{}
	for name, sql := range map[string]string{"up": planeRolesUp, "down": planeRolesDown} {
		stmts := m.splitSQL(sql)
		var doStmt string
		for _, s := range stmts {
			ts := strings.TrimSpace(s)
			for _, fragment := range []string{"END IF;", "END LOOP;", "$$;", "BEGIN", "END", "LOOP"} {
				if ts == fragment {
					t.Fatalf("%s: DO block was shredded — stray fragment %q", name, ts)
				}
			}
			if strings.Contains(s, "openidx_issue") {
				doStmt = s
			}
		}
		require.NotEmpty(t, doStmt, "%s: no intact DO statement naming the plane roles", name)
		assert.Contains(t, doStmt, "$$", "%s: DO block not intact in one statement", name)
		assert.Contains(t, doStmt, "END LOOP", "%s: the loop did not survive in the same statement", name)
	}
}

// The numbers are a decision recorded in the design (§4.1, §5.5), so they are
// pinned here rather than left to whoever edits the SQL next.
func TestV189CarriesTheDesignsTimeouts(t *testing.T) {
	for role, want := range map[string]string{
		"openidx_issue": "2s",
		"openidx_admin": "10s",
		"openidx_event": "30s",
	} {
		assert.Contains(t, planeRolesUp, fmt.Sprintf("('%s', '%s',", role, want),
			"%s must carry the design's statement_timeout", role)
	}
	// A plane role that bypassed RLS would not fail; it would return every
	// tenant's rows. The word has to be there on every one of them.
	assert.Equal(t, 1, strings.Count(planeRolesUp, "NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT IN ROLE openidx_app"),
		"the CREATE must spell out NOBYPASSRLS and inherit from openidx_app")
	assert.Contains(t, planeRolesUp, "idle_in_transaction_session_timeout",
		"a statement timeout alone is bypassed by holding a transaction open")
}

// --- measured against a real PostgreSQL ------------------------------------

// planeRoleTestPassword is set on each role by applyV189, because the roles
// ship passwordless on purpose (v53's note: no secret in git, the password is
// set out of band at deploy). The test does exactly what a deployment does.
const planeRoleTestPassword = "plane-role-test-only"

// planeRoleDSN rewrites the superuser DSN to connect as `role`.
func planeRoleDSN(t *testing.T, role string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(superuserDSN(t))
	require.NoError(t, err)
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		role, planeRoleTestPassword, cfg.Host, cfg.Port, cfg.Database)
}

// superuserDSN is the connection that may CREATE ROLE. The application's own
// DSN cannot -- which is not an inconvenience but the point of v53, and the
// reason the chart provisions roles from a bootstrap hook rather than from the
// migration Job's own credential.
func superuserDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_SUPERUSER_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_SUPERUSER_DSN not set; skipping the plane-role tests (creating a role needs it)")
	}
	return dsn
}

// applyV189 runs v53 then v189 as the superuser, gives the roles a password so
// the test can log in as them, and arranges for Down to run after.
func applyV189(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	owner, err := pgx.Connect(ctx, superuserDSN(t))
	require.NoError(t, err, "connect as the superuser")
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	_, err = owner.Exec(ctx, rlsAppRoleUp)
	require.NoError(t, err, "v53 must apply first; v189 depends on openidx_app")
	_, err = owner.Exec(ctx, planeRolesUp)
	require.NoError(t, err, "apply v189")
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), planeRolesDown)
	})

	for _, role := range []string{"openidx_issue", "openidx_admin", "openidx_event"} {
		_, err = owner.Exec(ctx, fmt.Sprintf("ALTER ROLE %s PASSWORD %s",
			pgx.Identifier{role}.Sanitize(), quoteLiteral(planeRoleTestPassword)))
		require.NoError(t, err, "set a login password on %s", role)
	}
	return owner
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// The property the whole migration rests on: a plane role is exactly as
// tenant-scoped as openidx_app, because it inherits openidx_app's privileges
// and RLS policies apply to every role that has them.
//
// This is the assertion worth running rather than reasoning about. If the
// inheritance did NOT carry the policies, the role would either see nothing
// (an outage) or -- if a policy were ever written permissively -- see every
// tenant's rows. Only the server can say which.
func TestV189PlaneRolesInheritTheTenantBelt(t *testing.T) {
	owner := applyV189(t)
	ctx := context.Background()

	tbl := fmt.Sprintf("v189_probe_%d", os.Getpid())
	_, err := owner.Exec(ctx, fmt.Sprintf(`
		DROP TABLE IF EXISTS %s;
		CREATE TABLE %s (id text primary key, org_id uuid not null, secret text not null);
		ALTER TABLE %s ENABLE ROW LEVEL SECURITY;
		ALTER TABLE %s FORCE ROW LEVEL SECURITY;
		CREATE POLICY pol_org_scope ON %s AS RESTRICTIVE TO openidx_app
		  USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
		  WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
		CREATE POLICY pol_all ON %s FOR ALL TO openidx_app USING (true) WITH CHECK (true);
		GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO openidx_app;
		INSERT INTO %s VALUES
		  ('a', '11111111-1111-1111-1111-111111111111', 'tenant-a-secret'),
		  ('b', '22222222-2222-2222-2222-222222222222', 'tenant-b-secret');
	`, tbl, tbl, tbl, tbl, tbl, tbl, tbl, tbl))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), "DROP TABLE IF EXISTS "+tbl) })

	for _, role := range []string{"openidx_issue", "openidx_admin", "openidx_event"} {
		t.Run(role, func(t *testing.T) {
			conn, err := pgx.Connect(ctx, planeRoleDSN(t, role))
			require.NoError(t, err, "%s must be able to log in", role)
			defer conn.Close(ctx)

			// It can reach the table at all: the DML grant came through
			// openidx_app. Without the inheritance this is a permission error.
			var scoped string
			require.NoError(t, conn.QueryRow(ctx,
				`select set_config('app.org_id', '11111111-1111-1111-1111-111111111111', false)`).Scan(&scoped))

			var got string
			require.NoError(t, conn.QueryRow(ctx, "SELECT secret FROM "+tbl).Scan(&got))
			assert.Equal(t, "tenant-a-secret", got, "%s saw the wrong tenant", role)

			// And the belt holds: the other tenant's row is invisible, and a
			// write for it is refused.
			var n int
			require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n))
			assert.Equal(t, 1, n, "%s saw more than its own tenant's rows", role)

			_, err = conn.Exec(ctx,
				"INSERT INTO "+tbl+" VALUES ('x', '22222222-2222-2222-2222-222222222222', 'nope')")
			assert.Error(t, err, "%s was allowed to write for another tenant", role)

			// Belt-and-braces on the attribute itself: a role that carries
			// BYPASSRLS would have passed every assertion above while seeing
			// everything.
			var bypass bool
			require.NoError(t, owner.QueryRow(ctx,
				"SELECT rolbypassrls FROM pg_roles WHERE rolname = $1", role).Scan(&bypass))
			assert.False(t, bypass, "%s carries BYPASSRLS; the tenant belt is decorative for it", role)
		})
	}
}

// The acceptance criterion of task 2.4, run: a long query on the ADMIN role is
// cancelled by the SERVER, and the ISSUE role is untouched by it.
func TestV189AdminQueryIsCancelledAndIssueIsNot(t *testing.T) {
	applyV189(t)
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, planeRoleDSN(t, "openidx_admin"))
	require.NoError(t, err)
	defer admin.Close(ctx)

	// The role's own setting, as the server sees it -- not something the
	// client asked for.
	var timeout string
	require.NoError(t, admin.QueryRow(ctx, "SHOW statement_timeout").Scan(&timeout))
	assert.Equal(t, "10s", timeout, "the ADMIN role did not pick up its statement_timeout at login")

	// 15s of work against a 10s ceiling. No context deadline: the point is that
	// the SERVER ends this, not the client.
	start := time.Now()
	_, err = admin.Exec(ctx, "SELECT pg_sleep(15)")
	elapsed := time.Since(start)

	require.Error(t, err, "a 15s query survived the ADMIN role's 10s statement_timeout")
	assert.Contains(t, err.Error(), "canceling statement due to statement timeout")
	assert.Less(t, elapsed, 14*time.Second,
		"the query ran for %s; it should have been cancelled at ~10s", elapsed)
	assert.Greater(t, elapsed, 9*time.Second,
		"the query ended after %s, too early to have been the 10s timeout", elapsed)

	// The connection survives its own cancelled statement: a plane whose pool
	// had to reconnect after every timeout would be worse off than one with no
	// timeout at all.
	var one int
	require.NoError(t, admin.QueryRow(ctx, "SELECT 1").Scan(&one),
		"the connection did not survive the cancellation")

	// ISSUE is tighter, and independent: it is a separate login with its own
	// setting, so nothing the ADMIN session did reached it.
	issue, err := pgx.Connect(ctx, planeRoleDSN(t, "openidx_issue"))
	require.NoError(t, err)
	defer issue.Close(ctx)

	require.NoError(t, issue.QueryRow(ctx, "SHOW statement_timeout").Scan(&timeout))
	assert.Equal(t, "2s", timeout)

	// The login path's own queries are microseconds; this proves the ceiling is
	// nowhere near them.
	start = time.Now()
	require.NoError(t, issue.QueryRow(ctx, "SELECT 1").Scan(&one),
		"the ISSUE role could not run a trivial query")
	assert.Less(t, time.Since(start), time.Second)
}

// A statement timeout alone is bypassed by BEGIN, one fast query, and holding
// the transaction open: the backend stays pinned and its locks stay held. This
// is why the migration sets idle_in_transaction_session_timeout too.
func TestV189IdleTransactionsAreClosedOut(t *testing.T) {
	applyV189(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, planeRoleDSN(t, "openidx_issue"))
	require.NoError(t, err)
	defer conn.Close(ctx)

	var idle string
	require.NoError(t, conn.QueryRow(ctx, "SHOW idle_in_transaction_session_timeout").Scan(&idle))
	assert.Equal(t, "1min", idle,
		"the ISSUE role can hold a transaction open indefinitely, which pins a backend and blocks vacuum")
}
