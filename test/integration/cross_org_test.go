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
func seedUserInOrg(t *testing.T, db *pgxpool.Pool, orgID, username, email string) string {
	t.Helper()
	var id string
	err := db.QueryRow(context.Background(),
		`INSERT INTO users (username, email, enabled, org_id)
		 VALUES ($1, $2, true, $3)
		 RETURNING id`, username, email, orgID).Scan(&id)
	require.NoError(t, err, "seed user %s in org %s", username, orgID)
	return id
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
		_, _ = db.Exec(context.Background(), "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	userB := seedUserInOrg(t, db, orgB, "xorg-user-"+suffix, "xorg-"+suffix+"@example.test")
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userB)
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
