package database

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- error classification -------------------------------------------------
//
// This is the hinge of the whole mechanism: get it wrong in one direction and
// a dead replica keeps failing reads; get it wrong in the other and a WRITE
// that reached Reader() is silently re-aimed at the primary.

func TestIsReplicaInfraError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a failure", nil, false},
		{"a dial failure is the replica not answering", errors.New("dial tcp 10.0.0.9:5432: connect: connection refused"), true},
		{"a pool that cannot hand out a connection", errors.New("timeout: pool exhausted"), true},

		// The server answered. The statement is at fault and the primary would
		// reject it identically.
		{"a syntax error is the query, not the replica", &pgconn.PgError{Code: "42601", Message: "syntax error"}, false},
		{"a wrapped PgError is still the query", errors.Join(errors.New("exec: "), &pgconn.PgError{Code: "42P01"}), false},

		// The one that matters most: a write on a read-only replica must stay
		// an error. Retrying it on the primary would make "NEVER use Reader()
		// for writes" unenforceable, and would do the write.
		{"a write on a read-only replica must NOT be retried on the primary",
			&pgconn.PgError{Code: "25006", Message: "cannot execute INSERT in a read-only transaction"}, false},

		// The caller gave up; the primary would fail on the same dead deadline.
		{"a cancelled context is the caller, not the replica", context.Canceled, false},
		{"an expired deadline is the caller, not the replica", context.DeadlineExceeded, false},
		{"no rows is an answer", pgx.ErrNoRows, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isReplicaInfraError(c.err))
		})
	}
}

// --- the breaker ----------------------------------------------------------

func TestReplicaBreaker_opensOnlyAfterRepeatedFailures(t *testing.T) {
	var b replicaBreaker
	now := time.Now()

	// One or two failures are not an outage: a single dial can fail for
	// reasons that are gone by the next request, and opening gives up the
	// offload for a whole cooldown.
	for i := 1; i < replicaBreakerThreshold; i++ {
		b.recordFailure(now)
		require.False(t, b.isOpen(now), "breaker opened after %d failure(s)", i)
	}
	b.recordFailure(now)
	assert.True(t, b.isOpen(now), "breaker did not open at the threshold")
}

func TestReplicaBreaker_successClosesIt(t *testing.T) {
	var b replicaBreaker
	now := time.Now()
	for i := 0; i < replicaBreakerThreshold; i++ {
		b.recordFailure(now)
	}
	require.True(t, b.isOpen(now))
	b.recordSuccess()
	assert.False(t, b.isOpen(now), "a success did not close the breaker")
}

// The cooldown expiring must not declare the replica healthy — it lets ONE
// call through to find out. A breaker that closed itself on a timer would
// send a burst of traffic at a replica that is still down.
func TestReplicaBreaker_cooldownProbesRatherThanAssumes(t *testing.T) {
	var b replicaBreaker
	now := time.Now()
	for i := 0; i < replicaBreakerThreshold; i++ {
		b.recordFailure(now)
	}
	require.True(t, b.isOpen(now))

	after := now.Add(replicaBreakerCooldown + time.Second)
	require.False(t, b.isOpen(after), "the breaker stayed open past its cooldown")

	// The probe fails: straight back to open, without needing a fresh run of
	// threshold failures.
	b.recordFailure(after)
	assert.True(t, b.isOpen(after), "a failed probe did not re-open the breaker")
}

// --- the wiring -----------------------------------------------------------

func TestWithFallback_isANoOpWithoutAReplica(t *testing.T) {
	primary := &ScopedPool{}
	assert.Nil(t, primary.fallbackTarget(), "the primary must have no fallback of its own")
	assert.False(t, primary.breakerIsOpen(), "the primary must never route around itself")

	// Guarding against the loop: a pool must not fall back to itself.
	assert.Same(t, primary, primary.withFallback(primary))
	assert.Nil(t, primary.fallbackTarget())

	var nilPool *ScopedPool
	assert.Nil(t, nilPool.withFallback(primary))
}

// A failure on a pool that has no fallback must not be counted or retried;
// the primary failing is simply the primary failing.
func TestNoteReplicaResult_primaryFailuresAreNotFallbacks(t *testing.T) {
	primary := &ScopedPool{}
	assert.False(t, primary.noteReplicaResult(errors.New("connection refused")))
}

// --- measured: a replica that is actually gone ----------------------------

// TestReaderFallback_deadReplicaStillServesReads is the acceptance criterion of
// task 2.3, run rather than asserted: with the replica pointed at a port
// nothing listens on, every read still answers — from the primary.
//
// Before readerfallback.go this test could not have passed. Reader() handed
// back the dead pool unconditionally and every ADMIN-plane read failed until
// the process was restarted, while the non-critical replica checker kept
// readiness green.
func TestReaderFallback_deadReplicaStillServesReads(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	// A pool that parses but cannot connect: the shape of a replica that has
	// gone away (failover, reboot, partition, maintenance window).
	deadCfg, err := pgxpool.ParseConfig(deadReplicaDSN(t))
	require.NoError(t, err)
	deadCfg.ConnConfig.ConnectTimeout = 2 * time.Second
	dead, err := pgxpool.NewWithConfig(context.Background(), deadCfg)
	require.NoError(t, err, "NewWithConfig is lazy; it must not dial here")
	t.Cleanup(dead.Close)

	db.readPool = NewScopedPool(dead).withFallback(db.Pool)
	require.True(t, db.HasReadReplica())

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	// QueryRow: the commonest read-path shape. The failure surfaces at Scan.
	var got string
	require.NoError(t, db.Reader().QueryRow(ctxA, "SELECT secret FROM "+tbl).Scan(&got),
		"a dead replica must not fail the read")
	assert.Equal(t, "tenant-a-secret", got, "the fallback must still be tenant-scoped")

	// Query.
	rows, err := db.Reader().Query(ctxA, "SELECT secret FROM "+tbl)
	require.NoError(t, err)
	var n int
	for rows.Next() {
		n++
	}
	rows.Close()
	require.NoError(t, rows.Err())
	assert.Equal(t, 1, n, "the fallback read saw the wrong number of rows")

	// Begin.
	tx, err := db.Reader().Begin(ctxA)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctxA, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-a-secret", got)
	require.NoError(t, tx.Rollback(ctxA))

	// By now the breaker is open, so the reads above cost a handful of failed
	// dials rather than one per request for the length of the outage.
	assert.True(t, db.readPool.breaker.isOpen(time.Now()),
		"repeated failures did not open the breaker; every request would keep dialling a dead replica")

	// And it still serves, now without touching the replica at all.
	require.NoError(t, db.Reader().QueryRow(ctxA, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-a-secret", got)
}

// The other half of the contract: a replica that IS answering must serve the
// read itself, not quietly hand everything to the primary. A fallback that
// always falls back is not an offload.
func TestReaderFallback_ahealthyReplicaServesItsOwnReads(t *testing.T) {
	pool := openTestPool(t)
	withMode(t, RLSModeLocal)
	db := seedTenantTable(t, pool, orgA, orgB)
	tbl := probeTable(t)

	// The same server standing in for the replica: what matters here is that a
	// pool which answers is not routed around.
	replica := openTestPool(t)
	db.readPool = NewScopedPool(replica).withFallback(db.Pool)

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	var got string
	require.NoError(t, db.Reader().QueryRow(ctxA, "SELECT secret FROM "+tbl).Scan(&got))
	assert.Equal(t, "tenant-a-secret", got)

	assert.False(t, db.readPool.breaker.isOpen(time.Now()),
		"a healthy replica opened the breaker")
	assert.Zero(t, db.readPool.breaker.consecutive.Load(),
		"a successful read left a failure counted against the replica")
}

// deadReplicaDSN points at a port on the test host that nothing listens on.
func deadReplicaDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("TEST_POSTGRES_DEAD_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://openidx_app:nobody@127.0.0.1:1/openidx_rls?sslmode=disable"
}
