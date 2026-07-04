//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestComposeMigrateSeedProducesRLSInstall proves the compose model
// (migrate-from-empty + seed.sql) yields a login-capable, RLS-enforced schema.
// Uses a throwaway DB + a dedicated throwaway role, so it mutates nothing shared
// (never touches the openidx_app role).
func TestComposeMigrateSeedProducesRLSInstall(t *testing.T) {
	adminDSN := integrationDSN(t) // skips if no DB
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	defer admin.Close()
	dbName := fmt.Sprintf("compose_seed_test_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err, "create throwaway DB")
	t.Cleanup(func() {
		c, e := pgxpool.New(context.Background(), adminDSN)
		if e == nil {
			defer c.Close()
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		}
	})

	u, err := url.Parse(adminDSN)
	require.NoError(t, err)
	u.Path = "/" + dbName
	probeDSN := u.String()

	probe, err := pgxpool.New(ctx, probeDSN)
	require.NoError(t, err)
	defer probe.Close()
	require.NoError(t, migrations.NewMigrator(probe, zap.NewNop()).MigrateTo(ctx, -1),
		"migrate-from-empty must reach latest cleanly")

	seedAssertCount(t, probe, "SELECT count(*) FROM users WHERE username='admin' AND password_hash <> ''", 1, "admin user")
	seedAssertCount(t, probe, "SELECT count(*) FROM oauth_clients WHERE client_id='admin-console'", 1, "admin-console client")
	seedAssertAtLeast(t, probe, "SELECT count(*) FROM user_roles ur JOIN users u ON u.id=ur.user_id JOIN roles r ON r.id=ur.role_id WHERE u.username='admin' AND r.name='admin'", 1, "admin holds admin role")

	seedSQL, err := os.ReadFile("../../deployments/docker/seed.sql")
	require.NoError(t, err)
	_, err = probe.Exec(ctx, string(seedSQL))
	require.NoError(t, err, "seed.sql must apply cleanly")
	seedAssertAtLeast(t, probe, "SELECT count(*) FROM role_permissions", 5, "role_permissions seeded")

	var forced bool
	require.NoError(t, probe.QueryRow(ctx, "SELECT relforcerowsecurity FROM pg_class WHERE relname='users'").Scan(&forced))
	require.True(t, forced, "users must be FORCE-RLS")

	// Sanity: the admin user exists (superuser bypasses RLS), so the 0 rows the
	// probe role sees below is RLS filtering — not an empty or broken table.
	var total int
	require.NoError(t, probe.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&total))
	require.Positive(t, total, "users table must be non-empty (else the fail-closed check is vacuous)")

	rolePool := seedThrowawayRolePool(t, probe, probeDSN)
	defer rolePool.Close()
	var n int
	require.NoError(t, rolePool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n))
	require.Equal(t, 0, n, "no-GUC query as NOSUPERUSER must see 0 rows (fail-closed)")

	// And with the org GUC set to the default org, the same role sees rows — proving
	// the policy filters by app.org_id, not that the role is simply denied access.
	// Use a transaction so the tx-local set_config and the SELECT share one
	// connection (a pool would otherwise route them to different sessions).
	tx, err := rolePool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "SELECT set_config('app.org_id', '00000000-0000-0000-0000-000000000010', true)")
	require.NoError(t, err)
	var scoped int
	require.NoError(t, tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&scoped))
	require.Positive(t, scoped, "with app.org_id set, the NOSUPERUSER role must see default-org rows")
}

func seedAssertCount(t *testing.T, db *pgxpool.Pool, q string, want int, what string) {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(context.Background(), q).Scan(&n))
	require.Equal(t, want, n, what)
}

func seedAssertAtLeast(t *testing.T, db *pgxpool.Pool, q string, min int, what string) {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(context.Background(), q).Scan(&n))
	require.GreaterOrEqual(t, n, min, what)
}

// seedThrowawayRolePool creates a dedicated NOSUPERUSER role scoped to THIS
// throwaway DB. Never touches the shared openidx_app role.
func seedThrowawayRolePool(t *testing.T, admin *pgxpool.Pool, probeDSN string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := fmt.Sprintf("rls_probe_%d", time.Now().UnixNano()%1000000)
	pw := "probe_pw"
	_, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'", role, pw))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+role) })
	for _, g := range []string{
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT ON users TO " + role,
	} {
		_, err := admin.Exec(ctx, g)
		require.NoError(t, err)
	}
	u, err := url.Parse(probeDSN)
	require.NoError(t, err)
	u.User = url.UserPassword(role, pw)
	pool, err := pgxpool.New(ctx, u.String())
	require.NoError(t, err)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("probe role cannot connect (pg_hba?): %v", err)
	}
	return pool
}
