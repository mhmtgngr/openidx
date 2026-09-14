package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// A SWEEP WITH NO STOPPING CONDITION LOOKS EXACTLY LIKE A SWEEP THAT WORKS.
//
// sweepStaleGuacGrants revokes the per-connection READ that an ended PAM session
// left behind on a standing Guacamole account -- the safety net for the sessions
// nothing else cleans up, the browser-closed ones. It wrote nothing, so the rows
// it had just handled matched its predicate again five minutes later, and again
// after that: a session that ended in March was still being revoked in June.
// Re-revoking an absent grant is a tolerated 404, which is why this was silent.
// The sweep never failed, so it looked like it was working.
//
// The waste (N replicas x 200 rows x 12 ticks an hour of broker calls that do
// nothing) is not the part that matters. The query carries LIMIT 200 with no
// progress marker, so once more than two hundred rows match -- which grows as an
// install ages and never shrinks -- the sweep revisits an arbitrary two hundred
// and the rest may never be reached. The grants that most need revoking are
// exactly the ones that can sit behind that limit indefinitely.
//
// So the measurement is not "does it revoke", it is "does it STOP": the second
// pass must call the broker zero times. On the old code it called it twice
// again, and would have forever.
func TestTheStaleGuacGrantSweepStopsWhenItIsDone(t *testing.T) {
	pool := openSweepPool(t)
	var calls atomic.Int64
	svc, ids := seedGuacGrants(t, pool, &calls)
	ctx := context.Background()

	svc.sweepStaleGuacGrants(ctx)
	assert.Equal(t, int64(2), calls.Load(),
		"the ended session and the twelve-hour-stale one are revoked; the live one is not")
	assert.NotEmpty(t, revokedAt(t, pool, ids["ended"]))
	assert.NotEmpty(t, revokedAt(t, pool, ids["stale"]))
	assert.Empty(t, revokedAt(t, pool, ids["live"]),
		"an active session was revoked mid-use")

	svc.sweepStaleGuacGrants(ctx)
	assert.Equal(t, int64(2), calls.Load(),
		"the second pass revoked the same grants again -- the sweep has no stopping condition, "+
			"so its LIMIT is a ceiling rather than a batch size and the grants behind it are never reached")
}

// The other half, which is what keeps the marker honest: a revoke the broker
// REFUSES must not be recorded as done. The row stays unmarked and the next tick
// tries again -- the same posture the lifecycle sweep takes with Guacamole
// session termination, and for the same reason: a grant marked revoked while the
// access survives is the silent hole this sweep exists to close.
func TestARefusedRevokeIsNotRecordedAsDone(t *testing.T) {
	pool := openSweepPool(t)
	var calls atomic.Int64
	svc, ids := seedGuacGrants(t, pool, &calls)
	// 500 is a broker failure, not the tolerated "grant was already absent" 404.
	svc.guacamoleClient.baseURL = failingGuacServer(t, &calls)
	ctx := context.Background()

	svc.sweepStaleGuacGrants(ctx)
	assert.Equal(t, int64(2), calls.Load(), "it still tried")
	assert.Empty(t, revokedAt(t, pool, ids["ended"]),
		"a refused revoke was marked done; the grant survives and nothing will try again")

	svc.guacamoleClient.baseURL = okGuacServer(t, &calls)
	svc.sweepStaleGuacGrants(ctx)
	assert.Equal(t, int64(4), calls.Load(), "the next tick retries what failed")
	assert.NotEmpty(t, revokedAt(t, pool, ids["ended"]))
}

func okGuacServer(t *testing.T, calls *atomic.Int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func failingGuacServer(t *testing.T, calls *atomic.Int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`broker down`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// seedGuacGrants builds the three rows the sweep has to tell apart and nothing
// else: a session that ended, one still marked active but started thirteen hours
// ago, and one that is genuinely live.
func seedGuacGrants(t *testing.T, pool *pgxpool.Pool, calls *atomic.Int64) (*Service, map[string]string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS pam_entry_sessions, pam_entries;
		CREATE TABLE pam_entries (id uuid primary key, reach_mode text);
		CREATE TABLE pam_entry_sessions (
			id uuid primary key, entry_id uuid NOT NULL, status text NOT NULL,
			guac_username text, guac_connection_id text,
			started_at timestamptz NOT NULL DEFAULT NOW(),
			ended_at timestamptz, guac_revoked_at timestamptz);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS pam_entry_sessions, pam_entries;`)
	})

	entry := uuid.NewString()
	ids := map[string]string{"ended": uuid.NewString(), "stale": uuid.NewString(), "live": uuid.NewString()}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO pam_entries (id, reach_mode) VALUES ($1, 'direct')`, []any{entry}},
		{`INSERT INTO pam_entry_sessions (id, entry_id, status, guac_username, guac_connection_id, started_at, ended_at)
			VALUES ($1, $2, 'ended', 'u-ended', 'c1', NOW() - interval '2 hours', NOW() - interval '1 hour')`,
			[]any{ids["ended"], entry}},
		{`INSERT INTO pam_entry_sessions (id, entry_id, status, guac_username, guac_connection_id, started_at)
			VALUES ($1, $2, 'active', 'u-stale', 'c2', NOW() - interval '13 hours')`,
			[]any{ids["stale"], entry}},
		{`INSERT INTO pam_entry_sessions (id, entry_id, status, guac_username, guac_connection_id, started_at)
			VALUES ($1, $2, 'active', 'u-live', 'c3', NOW() - interval '5 minutes')`,
			[]any{ids["live"], entry}},
	} {
		_, err = pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err, seed.sql)
	}

	gc := &GuacamoleClient{
		baseURL: okGuacServer(t, calls), dataSource: "postgresql", authToken: "t",
		httpClient: testResilient(http.DefaultClient), logger: zap.NewNop(),
		perUserIdentities: true,
	}
	svc := &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop(), guacamoleClient: gc}
	return svc, ids
}

func revokedAt(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var s *string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT guac_revoked_at::text FROM pam_entry_sessions WHERE id = $1`, id).Scan(&s))
	if s == nil {
		return ""
	}
	return *s
}
