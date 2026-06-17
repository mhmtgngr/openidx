//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationDB opens a pool against the test database. It reads DATABASE_URL,
// falling back to the local docker-compose DSN built from POSTGRES_PASSWORD.
// If neither is usable the cross-org suite is skipped (it needs direct seeding,
// unlike the HTTP-only helpers).
func integrationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		pw := os.Getenv("POSTGRES_PASSWORD")
		if pw == "" {
			t.Skip("DATABASE_URL/POSTGRES_PASSWORD not set; skipping cross-org DB seeding test")
		}
		dsn = fmt.Sprintf("postgres://openidx:%s@localhost:5432/openidx?sslmode=disable", pw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("cannot connect to test DB: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("test DB not reachable: %v", err)
	}
	return pool
}

// seedOrg upserts an organization by slug and returns its id.
func seedOrg(t *testing.T, db *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	err := db.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, status)
		 VALUES ($1, $2, 'active')
		 ON CONFLICT (slug) DO UPDATE SET updated_at = NOW()
		 RETURNING id`, "Cross-Org Test "+slug, slug).Scan(&id)
	require.NoError(t, err, "seed org %s", slug)
	return id
}

// seedUserInOrg inserts a user directly into the given org and returns its id.
// users is FORCE-RLS once migration v37 is applied, so the insert runs in a
// transaction that sets app.bypass_rls — a raw pool connection carries no org
// scope and would otherwise fail the policy's WITH CHECK.
func seedUserInOrg(t *testing.T, db *pgxpool.Pool, orgID, username, email string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `select set_config('app.bypass_rls', 'on', true)`)
	require.NoError(t, err)
	var id string
	err = tx.QueryRow(ctx,
		`INSERT INTO users (username, email, enabled, org_id)
		 VALUES ($1, $2, true, $3)
		 RETURNING id`, username, email, orgID).Scan(&id)
	require.NoError(t, err, "seed user %s in org %s", username, orgID)
	require.NoError(t, tx.Commit(ctx))
	return id
}

// bypassExec runs a statement with app.bypass_rls set so test cleanup can touch
// FORCE-RLS tables (a raw pool connection carries no org scope). Best-effort.
func bypassExec(t *testing.T, db *pgxpool.Pool, sql string, args ...interface{}) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `select set_config('app.bypass_rls', 'on', true)`); err != nil {
		return
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// TestCrossOrgIsolation verifies the v1.7.0 enforcement guarantee: a request
// scoped (via X-Org-Slug) to org A cannot read org B's resource — it gets 404
// (anti-enumeration), not 403 — while the same resource reads 200 under org B.
//
// Requires the running stack (make dev-infra) with the tenant resolver wired and
// DefaultOrgFallback off. Run: make test-integration.
func TestCrossOrgIsolation(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	slugA := "xorg-a-" + suffix
	slugB := "xorg-b-" + suffix

	orgA := seedOrg(t, db, slugA)
	orgB := seedOrg(t, db, slugB)
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	userB := seedUserInOrg(t, db, orgB, "xorg-user-"+suffix, "xorg-"+suffix+"@example.test")
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM users WHERE id = $1", userB)
	})

	token := getAdminToken(t)
	url := identityURL + "/api/v1/identity/users/" + userB

	t.Run("same org reads 200", func(t *testing.T) {
		status, _ := apiRequestWithOrg(t, "GET", url, "", token, slugB)
		assert.Equal(t, 200, status, "org B should read its own user")
	})

	t.Run("cross org reads 404 not 403", func(t *testing.T) {
		status, _ := apiRequestWithOrg(t, "GET", url, "", token, slugA)
		assert.Equal(t, 404, status, "org A must not see org B's user (404, anti-enumeration)")
	})

	t.Run("platform-admin X-Org-ID cross-org read is audited", func(t *testing.T) {
		before := crossOrgAuditCount(t, db, orgB)
		status, _ := apiRequestWithOrgID(t, "GET", url, "", token, orgB)
		if status != 200 {
			t.Skipf("admin is not a platform admin in this environment (status %d); skipping audited-bypass assertion", status)
		}
		// Give the synchronous audit insert a beat (it runs inline in the resolver).
		after := crossOrgAuditCount(t, db, orgB)
		assert.Greater(t, after, before, "platform-admin cross-org read must write an audit_events row")
	})
}

func crossOrgAuditCount(t *testing.T, db *pgxpool.Pool, orgID string) int {
	t.Helper()
	var n int
	err := db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'platform_admin_cross_org_access' AND org_id = $1`, orgID).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestRLSBelt is the v1.8.0 ship gate: Row-Level Security blocks cross-tenant
// reads even when the app-layer filter is "broken" (a raw SELECT that forgets to
// scope by org). It runs as the same DB role the app uses (the table owner), so
// FORCE ROW LEVEL SECURITY must be active for the policy to apply — the test
// asserts that and skips with guidance if migration v37 hasn't been applied.
//
// All statements run on a single acquired connection so the session GUCs
// (app.org_id / app.bypass_rls) we set with set_config(...,false) persist for
// the whole test, mimicking what the production pool checkout hook does.
func TestRLSBelt(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	ctx := context.Background()

	var forced bool
	if err := db.QueryRow(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'users'`).Scan(&forced); err != nil {
		t.Fatalf("checking RLS state: %v", err)
	}
	if !forced {
		t.Skip("FORCE ROW LEVEL SECURITY not active on users — migration v37 not applied to this DB; skipping RLS belt test")
	}

	conn, err := db.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	setScope := func(orgID, bypass string) {
		_, err := conn.Exec(ctx,
			`select set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
			orgID, bypass)
		require.NoError(t, err)
	}
	count := func(where string, arg string) int {
		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM users WHERE "+where, arg).Scan(&n))
		return n
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var orgA, orgB, userB string

	// Seed cross-org rows under bypass (FORCE RLS would otherwise reject the
	// WITH CHECK on the org-B insert from an unset-org session).
	setScope("", "on")
	require.NoError(t, conn.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, status) VALUES ($1,$2,'active') RETURNING id`,
		"RLS A "+suffix, "rls-a-"+suffix).Scan(&orgA))
	require.NoError(t, conn.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, status) VALUES ($1,$2,'active') RETURNING id`,
		"RLS B "+suffix, "rls-b-"+suffix).Scan(&orgB))
	require.NoError(t, conn.QueryRow(ctx,
		`INSERT INTO users (username, email, enabled, org_id) VALUES ($1,$2,true,$3) RETURNING id`,
		"rls-user-"+suffix, "rls-"+suffix+"@example.test", orgB).Scan(&userB))
	t.Cleanup(func() {
		c, err := db.Acquire(context.Background())
		if err != nil {
			return
		}
		defer c.Release()
		_, _ = c.Exec(context.Background(), `select set_config('app.bypass_rls','on',false)`)
		_, _ = c.Exec(context.Background(), "DELETE FROM users WHERE id=$1", userB)
		_, _ = c.Exec(context.Background(), "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	t.Run("scoped to org A: cannot see org B's user even by id (404-equivalent)", func(t *testing.T) {
		setScope(orgA, "off")
		assert.Equal(t, 0, count("org_id = $1", orgB), "org A must not see org B rows")
		assert.Equal(t, 0, count("id = $1", userB), "org A must not see org B's user by id")
	})

	t.Run("scoped to org B: sees its own user", func(t *testing.T) {
		setScope(orgB, "off")
		assert.Equal(t, 1, count("id = $1", userB), "org B sees its own user")
	})

	t.Run("no scope set: fail-closed (0 rows)", func(t *testing.T) {
		setScope("", "off")
		assert.Equal(t, 0, count("id = $1", userB), "unset app.org_id must read nothing")
	})

	t.Run("bypass: sees across orgs", func(t *testing.T) {
		setScope("", "on")
		assert.Equal(t, 1, count("id = $1", userB), "bypass sees org B's user from any session")
	})
}
