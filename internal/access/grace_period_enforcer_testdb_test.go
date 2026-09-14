package access

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// THE GRACE-PERIOD ENFORCER SUSPENDS A DEVICE AND SAYS SO IN THE AUDIT TRAIL,
// and those two facts are what make it worth measuring rather than reading.
//
// The census's other `idempotent` entries rest on a self-clearing predicate and
// write nothing else. This one also EMITS: every agent it suspends gets an
// `agent.suspended` row in unified_audit_events. That is the exact shape that
// was wrong elsewhere in this tree -- the Guacamole external audit sync inserted
// one row per replica for a single recorded session, and on a compliance product
// a duplicated audit row is a wrong answer, not waste.
//
// It is right here, and for a reason worth naming: the claim and the work are
// the SAME statement. `UPDATE ... WHERE compliance_status = 'grace_period' ...
// RETURNING` means a second replica blocks on the row lock, re-evaluates its
// predicate against the committed row, finds 'non_compliant', and returns no
// rows at all -- so it never reaches the audit insert. The database does the
// claiming, and RETURNING is what carries that claim into the emission.
//
// Eight concurrent enforcers, and each suspended agent must be announced once.
//
// EACH REPLICA GETS ITS OWN CONNECTION POOL, which is not tidiness. This sweep
// holds an open result set (the UPDATE's RETURNING cursor) on one connection
// while writing its audit rows on another, so a replica needs two connections at
// once. Eight goroutines sharing one pool is not eight replicas -- it is one
// process pretending, and it deadlocks on pool exhaustion the moment more than
// one of them gets rows back. That is an artifact of the pretence: in production
// each replica is its own process with its own pool. Found the hard way, by a
// mutation whose test hung instead of failing.
func TestEightConcurrentGracePeriodEnforcersSuspendAndAnnounceOnce(t *testing.T) {
	pool := openSweepPool(t)
	seedGracePeriodAgents(t, pool)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		h := &AgentAPIHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(replicaPool(t))}, logger: zap.NewNop()}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.enforceExpiredGracePeriods(ctx)
		}()
	}
	wg.Wait()

	assert.Equal(t, 2, agentsWith(t, pool, "suspended"),
		"both agents whose grace period expired are suspended")
	assert.Equal(t, 1, agentsWith(t, pool, "active"),
		"an agent still inside its grace period was suspended")
	assert.Equal(t, 2, suspendedAuditRows(t, pool),
		"the same suspension was announced more than once -- on a compliance product a duplicated "+
			"audit row is a wrong answer, not waste")

	// Settled: nothing left for a later tick to finish or repeat.
	settling := &AgentAPIHandler{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}
	settling.enforceExpiredGracePeriods(ctx)
	assert.Equal(t, 2, suspendedAuditRows(t, pool),
		"a pass after the concurrent run announced a suspension again")
}

// replicaPool opens a pool of this replica's own, so a replica holding its
// RETURNING cursor cannot starve another of connections.
func replicaPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_POSTGRES_DSN"))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func seedGracePeriodAgents(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS enrolled_agents, unified_audit_events;
		CREATE TABLE enrolled_agents (
			agent_id text primary key, ziti_identity_id text, status text NOT NULL,
			compliance_status text NOT NULL, last_report_at timestamptz);
		CREATE TABLE unified_audit_events (
			id uuid primary key, org_id uuid, source text, event_type text,
			user_id uuid, details jsonb, created_at timestamptz NOT NULL DEFAULT NOW());`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS enrolled_agents, unified_audit_events;`)
	})

	for _, seed := range []string{
		`INSERT INTO enrolled_agents (agent_id, status, compliance_status, last_report_at)
			VALUES ('a-late-1', 'active', 'grace_period', NOW() - interval '30 hours')`,
		`INSERT INTO enrolled_agents (agent_id, status, compliance_status, last_report_at)
			VALUES ('a-late-2', 'active', 'grace_period', NOW() - interval '25 hours')`,
		`INSERT INTO enrolled_agents (agent_id, status, compliance_status, last_report_at)
			VALUES ('a-inside', 'active', 'grace_period', NOW() - interval '2 hours')`,
	} {
		_, err = pool.Exec(ctx, seed)
		require.NoError(t, err, seed)
	}

}

func agentsWith(t *testing.T, pool *pgxpool.Pool, status string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM enrolled_agents WHERE status = $1`, status).Scan(&n))
	return n
}

func suspendedAuditRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM unified_audit_events WHERE event_type = 'agent.suspended'`).Scan(&n))
	return n
}
