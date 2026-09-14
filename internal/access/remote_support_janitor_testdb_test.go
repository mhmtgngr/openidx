package access

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// THE REMOTE-SUPPORT JANITOR IS THE CENSUS'S THIRD `idempotent` CLAIM, and by
// now the pattern is clear enough to state: the answer rests on a predicate that
// the statement's own write makes false, so a second replica matches nothing.
// Here the sweep sets status='expired' on rows WHERE status IN
// ('pending','active'), which is exactly that shape.
//
// What the first of these tests taught (lifecycle_sweep_testdb_test.go) is that
// counting rows does not check it. A sweep that re-applied itself every tick --
// rewriting ended_at with a fresh NOW() on rows it had already expired -- would
// move no count and pass. So this digests the VALUES: if a later replica rewrote
// a timestamp, the digest moves.
//
// That failure mode is not cosmetic here. ended_at is when the operator's
// support session stopped, and on a product that records those sessions for
// compliance an ended_at that drifts forward on every tick is a wrong answer to
// "when did this end", not a wasted write.
//
// The file's OTHER ticker is not a sweep: runPeer's is a per-websocket keepalive
// for one connected peer, which is per-process by definition -- the same shape as
// the audit event stream's, and gating it would mean a leader holding another
// pod's websocket open.
func TestEightConcurrentRemoteSupportJanitorsConvergeTheSameWay(t *testing.T) {
	pool := openSweepPool(t)
	h, live := seedRemoteSupportSessions(t, pool)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.expireOrphanSessions(ctx, time.Hour)
		}()
	}
	wg.Wait()

	after := remoteSupportState(t, pool)
	assert.Equal(t, "2", after["expired"], "both orphans are expired, once")
	assert.Equal(t, "1", after["still_open"], "the session with recent activity was aged out from under its operator")
	assert.Equal(t, "", endedAtOf(t, pool, live), "a live session was given an ended_at")

	// Settled: a further pass changes nothing, including the timestamps it
	// would rewrite if its predicate did not already exclude them.
	h.expireOrphanSessions(ctx, time.Hour)
	assert.Equal(t, after, remoteSupportState(t, pool),
		"a pass after the concurrent run moved something -- the sweep re-applies itself, so ended_at "+
			"drifts forward on every tick and 'when did this session end' has no stable answer")
}

func seedRemoteSupportSessions(t *testing.T, pool *pgxpool.Pool) (*RemoteSupportHandler, string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS remote_support_sessions;
		CREATE TABLE remote_support_sessions (
			id uuid primary key, agent_id text NOT NULL, status text NOT NULL,
			end_reason text, started_at timestamptz NOT NULL DEFAULT NOW(),
			ended_at timestamptz,
			last_activity_at timestamptz NOT NULL DEFAULT NOW());`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS remote_support_sessions;`) })

	live := uuid.NewString()
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO remote_support_sessions (id, agent_id, status, last_activity_at)
			VALUES (gen_random_uuid(), 'a1', 'pending', NOW() - interval '3 hours')`, nil},
		{`INSERT INTO remote_support_sessions (id, agent_id, status, last_activity_at)
			VALUES (gen_random_uuid(), 'a2', 'active', NOW() - interval '2 hours')`, nil},
		{`INSERT INTO remote_support_sessions (id, agent_id, status, last_activity_at)
			VALUES ($1, 'a3', 'active', NOW() - interval '1 minute')`, []any{live}},
	} {
		_, err = pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err, seed.sql)
	}

	// auditAgent stays nil: the sweep handles that explicitly, and the audit
	// trail is not what this measures.
	return &RemoteSupportHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}, live
}

// remoteSupportState digests everything the sweep can change, so a before/after
// comparison is one value rather than a list of assertions that can quietly stop
// covering a column -- and so a rewritten timestamp MOVES it.
func remoteSupportState(t *testing.T, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, q := range map[string]string{
		"expired":    `SELECT count(*)::text FROM remote_support_sessions WHERE status = 'expired'`,
		"still_open": `SELECT count(*)::text FROM remote_support_sessions WHERE status IN ('pending','active')`,
		"digest": `SELECT COALESCE(md5(string_agg(id::text || '|' || status || '|' ||
				COALESCE(ended_at::text,'') || '|' || COALESCE(end_reason,''), ',' ORDER BY id)), '')
			  FROM remote_support_sessions`,
	} {
		var v string
		require.NoError(t, pool.QueryRow(context.Background(), q).Scan(&v), q)
		out[name] = v
	}
	return out
}

func endedAtOf(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var s *string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT ended_at::text FROM remote_support_sessions WHERE id = $1`, id).Scan(&s))
	if s == nil {
		return ""
	}
	return *s
}
