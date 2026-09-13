package audit

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE COUNTER IS MONEY, so this is measured against a real PostgreSQL rather
// than reasoned about. The rollup is an INCREMENT, and two processes
// incrementing the same row from the same cursor is not a race a mock can have.
func openMeteringPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the usage metering tests (they need a real Postgres)")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	// At least two connections: the whole point is two replicas at once.
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// seedMetering applies v102's real SQL plus the one column of
// unified_audit_events the rollup reads.
func seedMetering(t *testing.T, pool *pgxpool.Pool, events int) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS usage_metering_cursor;
		DROP TABLE IF EXISTS usage_metering_daily;
		DROP TABLE IF EXISTS unified_audit_events;
		CREATE TABLE unified_audit_events (
			id uuid primary key, org_id uuid, user_id uuid, source text, event_type text,
			details jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL);`)
	require.NoError(t, err)
	for _, m := range migrations.All() {
		if m.Version == 102 {
			_, err = pool.Exec(ctx, m.UpSQL)
			require.NoError(t, err, "apply v102")
			break
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS usage_metering_cursor;
			DROP TABLE IF EXISTS usage_metering_daily; DROP TABLE IF EXISTS unified_audit_events;`)
	})

	org := uuid.NewString()
	base := time.Now().Add(-time.Hour).UTC()
	for i := 0; i < events; i++ {
		_, err = pool.Exec(ctx, `
			INSERT INTO unified_audit_events (id, org_id, source, event_type, details, created_at)
			VALUES ($1, $2, 'ziti', 'ziti.service.dialed', '{"service":"db"}'::jsonb, $3)`,
			uuid.NewString(), org, base.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
	}
	return &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}, org
}

func meteredTotal(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT COALESCE(SUM(count), 0) FROM usage_metering_daily").Scan(&n))
	return n
}

// Two replicas aggregating at the same moment must bill the customer for the
// events that happened, not for twice them.
func TestConcurrentRepicasDoNotDoubleBill(t *testing.T) {
	pool := openMeteringPool(t)
	const events = 40
	svc, _ := seedMetering(t, pool, events)
	w := &meteringWorker{svc: svc, logger: zap.NewNop()}
	ctx := orgctx.WithBypassRLS(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := w.aggregateBatch(ctx)
				if err != nil || n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(events), meteredTotal(t, pool),
		"four replicas rolled up the same events more than once: this is the number a customer is billed from")
}

// And the rollup still works at all: one pass counts every event exactly once.
func TestASinglePassCountsEveryEventOnce(t *testing.T) {
	pool := openMeteringPool(t)
	const events = 12
	svc, _ := seedMetering(t, pool, events)
	w := &meteringWorker{svc: svc, logger: zap.NewNop()}
	ctx := orgctx.WithBypassRLS(context.Background())

	n, err := w.aggregateBatch(ctx)
	require.NoError(t, err)
	assert.Equal(t, events, n)
	assert.Equal(t, int64(events), meteredTotal(t, pool))

	// The cursor advanced, so a second pass has nothing to do rather than
	// counting the same window again.
	n, err = w.aggregateBatch(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, int64(events), meteredTotal(t, pool))
}

// observedLogger returns a logger and a reader for what it recorded at error
// level, so a test can assert that a silent failure is not silent.
func observedLogger() (*zap.Logger, func() []observer.LoggedEntry) {
	core, recorded := observer.New(zapcore.ErrorLevel)
	return zap.New(core), func() []observer.LoggedEntry { return recorded.All() }
}

// A missing cursor row must be loud. Silently rolling nothing up for ever is
// the same amount of lost revenue as double-billing is of wrong revenue, and it
// looks like a healthy idle worker.
func TestAMissingCursorRowIsNotSilence(t *testing.T) {
	pool := openMeteringPool(t)
	svc, _ := seedMetering(t, pool, 3)
	_, err := pool.Exec(context.Background(), "DELETE FROM usage_metering_cursor")
	require.NoError(t, err)

	logs, obs := observedLogger()
	w := &meteringWorker{svc: svc, logger: logs}
	n, err := w.aggregateBatch(orgctx.WithBypassRLS(context.Background()))
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.NotEmpty(t, obs(), "a missing metering cursor must be reported, not treated as 'nothing to do'")
}
