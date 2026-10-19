package access

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// A DEVICE WHOSE AGENT STOPPED REPORTING LOSES ITS TRUST ONCE, AND SAYS SO ONCE.
//
// sweepSilentDevices claims a device by removing #device-trusted from its
// recorded identity in the same statement that finds it, like the grace
// enforcer it shares a ticker with. Eight concurrent sweeps must strip the
// silent device once, announce it once, and leave a live device and a device
// that was never trusted alone.
func TestEightConcurrentLivenessSweepsStripTrustOnce(t *testing.T) {
	dsn, pool := livenessScratch(t)
	seedLivenessAgents(t, pool)
	ctx := context.Background()
	conf := &config.Config{AgentLivenessTimeout: "10m"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		// Each replica its own pool, as in the grace-period test: a sweep
		// holds its RETURNING cursor while writing its audit row.
		rp, err := pgxpool.New(ctx, dsn)
		require.NoError(t, err)
		t.Cleanup(rp.Close)
		h := &AgentAPIHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(rp)}, logger: zap.NewNop(), conf: conf}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.sweepSilentDevices(ctx)
		}()
	}
	wg.Wait()

	assert.False(t, identityTrusted(t, pool, "a-silent"), "the silent device kept #device-trusted")
	assert.True(t, identityTrusted(t, pool, "a-live"), "a device reporting within the timeout lost its trust")
	assert.Equal(t, 1, auditRows(t, pool, "agent.stale"),
		"the silent device was announced more than once (or not at all)")
	assert.Equal(t, "active", agentStatus(t, pool, "a-silent"),
		"a silent device is suspended; it should stay active so its next report restores trust")

	settling := &AgentAPIHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop(), conf: conf}
	assert.Equal(t, 0, settling.sweepSilentDevices(ctx), "a later pass found something to do again")
	assert.Equal(t, 1, auditRows(t, pool, "agent.stale"))
}

// With AGENT_LIVENESS_TIMEOUT=0 the sweep does nothing at all.
func TestLivenessSweepOffDoesNothing(t *testing.T) {
	_, pool := livenessScratch(t)
	seedLivenessAgents(t, pool)
	h := &AgentAPIHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop(),
		conf: &config.Config{AgentLivenessTimeout: "0"}}
	assert.Equal(t, 0, h.sweepSilentDevices(context.Background()))
	assert.True(t, identityTrusted(t, pool, "a-silent"))
}

// livenessScratch is a database of the test's own: the shared test database
// carries the real schema, whose ziti_identities other objects depend on.
func livenessScratch(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	pool := db.Pool.Raw()
	return pool.Config().ConnString(), pool
}

func seedLivenessAgents(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS enrolled_agents, ziti_identities, unified_audit_events;
		CREATE TABLE enrolled_agents (
			agent_id text primary key, ziti_identity_id text, status text NOT NULL,
			compliance_status text NOT NULL, last_report_at timestamptz);
		CREATE TABLE ziti_identities (
			agent_id text primary key, attributes jsonb NOT NULL DEFAULT '[]', updated_at timestamptz);
		CREATE TABLE unified_audit_events (
			id uuid primary key, org_id uuid, source text, event_type text,
			user_id uuid, details jsonb, created_at timestamptz NOT NULL DEFAULT NOW());`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS enrolled_agents, ziti_identities, unified_audit_events;`)
	})
	for _, seed := range []string{
		`INSERT INTO enrolled_agents VALUES ('a-silent', 'z1', 'active', 'compliant', NOW() - interval '20 minutes')`,
		`INSERT INTO enrolled_agents VALUES ('a-live', 'z2', 'active', 'compliant', NOW() - interval '1 minute')`,
		`INSERT INTO enrolled_agents VALUES ('a-never', 'z3', 'active', 'non_compliant', NULL)`,
		`INSERT INTO ziti_identities VALUES ('a-silent', '["openidx-agent","device-a-silent","device-trusted"]')`,
		`INSERT INTO ziti_identities VALUES ('a-live', '["openidx-agent","device-a-live","device-trusted"]')`,
		`INSERT INTO ziti_identities VALUES ('a-never', '["openidx-agent","device-a-never"]')`,
	} {
		_, err = pool.Exec(ctx, seed)
		require.NoError(t, err, seed)
	}
}

func identityTrusted(t *testing.T, pool *pgxpool.Pool, agentID string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT attributes ? 'device-trusted' FROM ziti_identities WHERE agent_id = $1`, agentID).Scan(&ok))
	return ok
}

func auditRows(t *testing.T, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM unified_audit_events WHERE event_type = $1`, eventType).Scan(&n))
	return n
}

func agentStatus(t *testing.T, pool *pgxpool.Pool, agentID string) string {
	t.Helper()
	var s string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT status FROM enrolled_agents WHERE agent_id = $1`, agentID).Scan(&s))
	return s
}
