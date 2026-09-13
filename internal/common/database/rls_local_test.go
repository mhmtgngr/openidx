package database

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// These tests run against a real Postgres because the property under test is a
// Postgres property: that set_config(..., true) is reset at COMMIT and
// set_config(..., false) is not. A mock cannot fail the way this can.
//
// TEST_POSTGRES_DSN points at one (the CI job and the local dev loop both set
// it); without it the tests skip, the same contract the repo's other
// DB-backed tests use.
func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the RLS isolation tests (they need a real Postgres)")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	// ONE connection. This is the whole point: it forces every tenant in the
	// test to reuse the same backend, which is exactly what a transaction
	// pooler does to a fleet and what session-scoped state cannot survive.
	cfg.MaxConns = 1
	cfg.MinConns = 1
	configureRLS(cfg)
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// A row-level-security test that connects as a superuser proves nothing:
	// Postgres exempts superusers (and any role with BYPASSRLS) from every
	// policy, so all of these assertions would pass with the belt cut. That is
	// worse than having no test, because it reads as evidence. Production
	// connects as the non-owner, non-superuser openidx_app; so must this.
	var isSuper, canBypass bool
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&isSuper, &canBypass))
	require.Falsef(t, isSuper || canBypass,
		"TEST_POSTGRES_DSN connects as a role that bypasses RLS (superuser=%t bypassrls=%t). "+
			"Every isolation assertion here would pass vacuously. Point it at a role like production's openidx_app.",
		isSuper, canBypass)

	return pool
}

// seedTenantTable builds a FORCE-RLS table shaped like a real tenant table and
// seeds one row per org, then returns a DB handle over the single-connection
// pool.
func seedTenantTable(t *testing.T, pool *pgxpool.Pool, orgA, orgB string) *PostgresDB {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("rls_probe_%d", os.Getpid())
	_, err := pool.Exec(ctx, fmt.Sprintf(`
		DROP TABLE IF EXISTS %s;
		CREATE TABLE %s (id text primary key, org_id uuid not null, secret text not null);
		ALTER TABLE %s ENABLE ROW LEVEL SECURITY;
		ALTER TABLE %s FORCE ROW LEVEL SECURITY;
		CREATE POLICY pol_%s_org_scope ON %s
			USING (current_setting('app.bypass_rls', true) = 'on'
			       OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
			WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
			       OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
	`, name, name, name, name, name, name))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+name)
	})

	// Seed with the policy bypassed: the seeder is not a tenant.
	bypass := orgctx.WithBypassRLS(ctx)
	db := &PostgresDB{Pool: NewScopedPool(pool)}
	require.NoError(t, db.WithTx(bypass, func(tx pgx.Tx) error {
		for _, s := range []struct{ id, org, secret string }{
			{"a1", orgA, "tenant-a-secret"},
			{"b1", orgB, "tenant-b-secret"},
		} {
			if _, err := tx.Exec(bypass, "INSERT INTO "+name+" (id, org_id, secret) VALUES ($1,$2,$3)", s.id, s.org, s.secret); err != nil {
				return err
			}
		}
		return nil
	}))
	t.Setenv("RLS_PROBE_TABLE", name)
	return db
}

func probeTable(t *testing.T) string { t.Helper(); return os.Getenv("RLS_PROBE_TABLE") }

const (
	orgA = "11111111-1111-1111-1111-111111111111"
	orgB = "22222222-2222-2222-2222-222222222222"
)

// withMode sets the process-wide RLS mode for one test and restores it, so the
// two modes can be exercised in one package without leaking into each other.
func withMode(t *testing.T, m RLSMode) {
	t.Helper()
	rlsModeMu.Lock()
	prev, prevSet := rlsModeVal, rlsModeSet
	rlsModeMu.Unlock()
	SetRLSMode(m)
	t.Cleanup(func() {
		rlsModeMu.Lock()
		rlsModeVal, rlsModeSet = prev, prevSet
		rlsModeMu.Unlock()
	})
}

// The headline property. Two tenants, ONE connection, alternating: each must
// see only its own row. This is the shape a transaction pooler creates, and the
// shape that makes session-scoped state unsafe.
func TestRLSLocal_TwoTenantsSharingOneConnectionSeeOnlyTheirOwn(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	read := func(org string) []string {
		ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
		rows, err := db.Query(ctx, "SELECT secret FROM "+tbl+" ORDER BY id")
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			require.NoError(t, rows.Scan(&s))
			out = append(out, s)
		}
		require.NoError(t, rows.Err())
		return out
	}

	// Alternate tenants on the same backend, repeatedly: a scope that leaked
	// from the previous transaction would show up as the other tenant's row.
	for i := 0; i < 25; i++ {
		assert.Equal(t, []string{"tenant-a-secret"}, read(orgA), "iteration %d", i)
		assert.Equal(t, []string{"tenant-b-secret"}, read(orgB), "iteration %d", i)
	}
}

// The property that makes transaction pooling safe: after a scoped transaction
// commits, the connection carries NO scope. A query with no tenant context then
// sees zero rows (fail-closed), rather than the previous tenant's rows.
func TestRLSLocal_ScopeDoesNotSurviveTheTransaction(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	var n int
	require.NoError(t, db.QueryRow(ctxA, "SELECT count(*) FROM "+tbl).Scan(&n))
	require.Equal(t, 1, n, "tenant A sees its own row")

	// Straight at the pool, no scope, same connection: the GUC must be gone.
	var leaked string
	err := pool.QueryRow(context.Background(), "SELECT coalesce(current_setting('app.org_id', true), '')").Scan(&leaked)
	require.NoError(t, err)
	assert.Empty(t, leaked, "the tenant scope must not outlive its transaction; a pooler would hand this backend to another tenant")

	var after int
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT count(*) FROM "+tbl).Scan(&after))
	assert.Equal(t, 0, after, "with no scope the policy must yield zero rows, not the last tenant's")
}

// Concurrency: many goroutines, two tenants, one connection. Every read must be
// its own tenant's. A scope applied outside the transaction would interleave.
func TestRLSLocal_ConcurrentTenantsNeverCross(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 100; i++ {
		for _, tc := range []struct{ org, want string }{{orgA, "tenant-a-secret"}, {orgB, "tenant-b-secret"}} {
			wg.Add(1)
			go func(org, want string) {
				defer wg.Done()
				ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
				var got string
				if err := db.QueryRow(ctx, "SELECT secret FROM "+tbl).Scan(&got); err != nil {
					errs <- err
					return
				}
				if got != want {
					errs <- fmt.Errorf("CROSS-TENANT READ: org %s saw %q, wanted %q", org, got, want)
				}
			}(tc.org, tc.want)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// No tenant context at all is zero rows, in local mode as in session mode:
// fail-closed is the property the whole belt exists for.
func TestRLSLocal_NoTenantContextYieldsNoRows(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	var n int
	require.NoError(t, db.QueryRow(context.Background(), "SELECT count(*) FROM "+tbl).Scan(&n))
	assert.Equal(t, 0, n)
}

// The bypass marker still works in local mode: background and cross-org
// maintenance is the one path that spans tenants, and it must keep spanning.
func TestRLSLocal_BypassStillSeesEverything(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	var n int
	require.NoError(t, db.QueryRow(orgctx.WithBypassRLS(context.Background()), "SELECT count(*) FROM "+tbl).Scan(&n))
	assert.Equal(t, 2, n)

	// ...and the bypass does not outlive its transaction either.
	var leaked string
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT coalesce(current_setting('app.bypass_rls', true), '')").Scan(&leaked))
	assert.NotEqual(t, "on", leaked, "a leaked bypass marker would make the NEXT query see every tenant")
}

// Session mode must keep behaving exactly as it does today, so the flag is a
// real escape hatch rather than a one-way door.
func TestRLSSession_StillIsolatesTenants(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeSession)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	for i := 0; i < 10; i++ {
		var got string
		require.NoError(t, db.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: orgA}), "SELECT secret FROM "+tbl).Scan(&got))
		assert.Equal(t, "tenant-a-secret", got)
		require.NoError(t, db.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: orgB}), "SELECT secret FROM "+tbl).Scan(&got))
		assert.Equal(t, "tenant-b-secret", got)
	}
}

// Writes are scoped too: WITH CHECK must refuse a row written for another org.
func TestRLSLocal_WriteForAnotherTenantIsRefused(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	_, err := db.Exec(ctxA, "INSERT INTO "+tbl+" (id, org_id, secret) VALUES ('x1',$1,'smuggled')", orgB)
	require.Error(t, err, "a tenant must not be able to write a row into another tenant")

	// And the failed write left nothing behind.
	var n int
	require.NoError(t, db.QueryRow(orgctx.WithBypassRLS(context.Background()), "SELECT count(*) FROM "+tbl+" WHERE id='x1'").Scan(&n))
	assert.Equal(t, 0, n)
}

// A rolled-back transaction must release its connection; a leaked transaction
// on a one-connection pool deadlocks the next query, which is how a subtle
// lifetime bug in the wrappers would show up in production as a hang.
func TestRLSLocal_FailedQueriesDoNotLeakConnections(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	for i := 0; i < 5; i++ {
		// A statement error.
		_, err := db.Exec(ctxA, "SELECT does_not_exist()")
		require.Error(t, err)
		// A no-rows Scan.
		var s string
		err = db.QueryRow(ctxA, "SELECT secret FROM "+tbl+" WHERE id='nope'").Scan(&s)
		require.ErrorIs(t, err, pgx.ErrNoRows)
		// Rows closed without draining.
		rows, err := db.Query(ctxA, "SELECT secret FROM "+tbl)
		require.NoError(t, err)
		rows.Close()
	}

	// If any of the above leaked its transaction, this blocks forever on the
	// single connection rather than returning.
	var n int
	require.NoError(t, db.QueryRow(ctxA, "SELECT count(*) FROM "+tbl).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestParseRLSMode(t *testing.T) {
	assert.Equal(t, RLSModeSession, ParseRLSMode(""))
	assert.Equal(t, RLSModeSession, ParseRLSMode("locall"))
	assert.Equal(t, RLSModeLocal, ParseRLSMode(" Local "))
	assert.Equal(t, RLSModeLocal, ParseRLSMode("LOCAL"))
}

// The point of ScopedPool: a call site that was never edited — db.Pool.Query,
// exactly as ~1,950 of them are written across this repo — must carry the
// tenant scope in local mode. If this fails, the wrapper is decoration and the
// migration really is 1,950 hand edits.
func TestScopedPool_UneditedCallSitesAreScoped(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})

	// db.Pool.QueryRow — the single commonest shape in the codebase.
	var got string
	require.NoError(t, db.Pool.QueryRow(ctxA, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-a-secret", got)
	require.NoError(t, db.Pool.QueryRow(ctxB, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-b-secret", got)

	// db.Pool.Query
	rows, err := db.Pool.Query(ctxA, "SELECT secret FROM "+tbl)
	require.NoError(t, err)
	var n int
	for rows.Next() {
		n++
	}
	rows.Close()
	assert.Equal(t, 1, n, "an unedited db.Pool.Query must see one tenant's rows, not both")

	// db.Pool.Exec — a cross-tenant write is still refused.
	_, err = db.Pool.Exec(ctxA, "INSERT INTO "+tbl+" (id, org_id, secret) VALUES ('p1',$1,'x')", orgB)
	require.Error(t, err)

	// db.Pool.Begin — the ~25 call sites that run their own transaction.
	tx, err := db.Pool.Begin(ctxB)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctxB, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-b-secret", got)
	require.NoError(t, tx.Commit(ctxB))

	// And Raw() is the documented way out: no scope, so fail-closed.
	var raw int
	require.NoError(t, db.Pool.Raw().QueryRow(context.Background(), "SELECT count(*) FROM "+tbl).Scan(&raw))
	assert.Equal(t, 0, raw, "Raw() must NOT carry a scope; that is what makes it greppable and deliberate")
}

// SendBatch prepends the scope rather than wrapping a transaction; the caller
// must still read its own queries in the order it queued them.
func TestScopedPool_BatchIsScopedAndResultsLineUp(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	b := &pgx.Batch{}
	b.Queue("SELECT secret FROM " + tbl)
	b.Queue("SELECT count(*) FROM " + tbl)

	br := db.Pool.SendBatch(ctxA, b)
	var secret string
	require.NoError(t, br.QueryRow().Scan(&secret), "first result must be the caller's first query, not the scope statement")
	assert.Equal(t, "tenant-a-secret", secret)
	var count int
	require.NoError(t, br.QueryRow().Scan(&count))
	assert.Equal(t, 1, count)
	require.NoError(t, br.Close())
}
