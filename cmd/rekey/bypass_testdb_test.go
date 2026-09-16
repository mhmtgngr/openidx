package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// WHAT A REKEY THAT CANNOT SEE ANYTHING LOOKS LIKE.
//
// This binary reads and rewrites every tenant's encrypted columns, so it needs
// to read across tenants. It used to take app.bypass_rls best-effort, with the
// error discarded and nothing checking it took. Under FORCE ROW LEVEL SECURITY
// a connection with no tenant scope and no bypass does not fail: it sees ZERO
// ROWS. A rekey that sees nothing rewrites nothing, prints "0 rekeyed" and
// exits 0, and the next KEK rotation retires a key that is still decrypting
// live data.
//
// canSeeEveryTenant is the check that turns that into a refusal, and it can
// only be measured against a real server: whether a role is exempt from RLS,
// and whether a GUC took, are facts about PostgreSQL and not about Go.
func rekeyProbePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the rekey bypass check (it needs a real Postgres)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, pool.Ping(context.Background()))

	var exempt bool
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&exempt))
	require.False(t, exempt,
		"TEST_POSTGRES_DSN connects as a role that is exempt from row-level security; against that role this "+
			"check answers true whatever the setting says, and the test would be measuring nothing")
	return pool
}

func TestARekeyThatCannotSeeAcrossTenantsIsDetected(t *testing.T) {
	pool := rekeyProbePool(t)
	ctx := context.Background()

	// A plain pool, no bypass anywhere: exactly the state the old code would
	// have proceeded from, and reported a successful rekey of nothing.
	require.False(t, canSeeEveryTenant(ctx, pool),
		"a connection with no tenant scope and no bypass was reported as able to see every tenant")
}

// THE ONE THAT MEASURES THE ACTUAL BUG. A session GUC belongs to ONE backend,
// and a pool is many. The old code took the bypass with a single pool.Exec, so
// the connection that served it carried the setting and every other connection
// the pool opened did not -- reading zero rows, silently, under FORCE RLS.
//
// This forces the second connection into existence by holding the first, which
// is what the pool does on its own the moment a connection ages out, a health
// check churns one, or anything runs concurrently.
func TestEveryConnectionTheRekeyPoolOpensCarriesTheBypass(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the rekey bypass check (it needs a real Postgres)")
	}
	ctx := context.Background()

	pool, err := openRekeyPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	held, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer held.Release()
	second, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer second.Release()

	var firstPID, secondPID int
	require.NoError(t, held.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&firstPID))
	require.NoError(t, second.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&secondPID))
	require.NotEqual(t, firstPID, secondPID,
		"both acquisitions landed on the same backend, so this test is not measuring what it says it is")

	for _, c := range []struct {
		name string
		pid  int
		row  interface{ Scan(...any) error }
	}{
		{"first", firstPID, held.QueryRow(ctx, "SELECT COALESCE(current_setting('app.bypass_rls', true),'')")},
		{"second", secondPID, second.QueryRow(ctx, "SELECT COALESCE(current_setting('app.bypass_rls', true),'')")},
	} {
		var bypass string
		require.NoError(t, c.row.Scan(&bypass))
		require.Equal(t, "on", bypass,
			"the %s connection (pid %d) carries no bypass. Every query that lands on it reads zero rows under "+
				"FORCE RLS, and a rekey reports that as success", c.name, c.pid)
	}
}
