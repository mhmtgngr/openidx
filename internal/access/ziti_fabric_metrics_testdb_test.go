package access

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// THE FABRIC HEALTH TICK IS TWO KINDS OF WORK IN ONE FUNCTION, and the census
// question ("polls fabric health: if it only reads and reports, per-process is
// right; if it writes a shared health row, it is not") had both answers.
//
// The health check and the re-authentication are per-process and must run in
// every replica: each pod holds its own SDK session, and a pod that skipped its
// re-auth because another pod was leader would stay disconnected. The metrics
// are the opposite. Routers online, services count, identities count are
// properties of the FABRIC, so a row per replica is one fact written N times.
//
// The cost is not only storage. The fabric overview reads the most recent 50
// rows of ziti_metrics, and the cycle writes seven per tick: at one replica
// that window holds about three and a half minutes of history, and at eight it
// holds twenty-six seconds of the same instant, eight times over. This is the
// shape the census names outright -- the Guacamole audit sync was the same
// defect with a compliance consequence instead of a dashboard one.
//
// So the metric half is now gated per tick, and this measures it with eight
// replicas racing the same bucket against a real Redis and a real database.
func TestOnlyOneReplicaRecordsTheFabricMetricsPerTick(t *testing.T) {
	pool := openSweepPool(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS ziti_metrics;
		CREATE TABLE ziti_metrics (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			metric_type VARCHAR(100) NOT NULL,
			source VARCHAR(255) NOT NULL,
			value DOUBLE PRECISION NOT NULL,
			labels JSONB DEFAULT '{}',
			recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ziti_metrics;`) })

	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	status := &FabricHealthStatus{
		ControllerReachable: true, SDKReady: true,
		RoutersOnline: 3, RoutersTotal: 4, ServicesCount: 12,
		IdentitiesCount: 40, PoliciesCount: 7,
	}

	// Eight replicas, one ZitiManager each, one tick.
	const replicas = 8
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zm := &ZitiManager{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}
			zm.recordFabricMetrics(ctx, rdb, status, 1, nil)
		}()
	}
	wg.Wait()

	// The cycle writes seven metrics. Eight replicas must still write seven.
	assert.Equal(t, 7, metricRows(t, pool),
		"more than one replica recorded the fabric metrics for this tick; the overview's 50-row "+
			"window is now the same instant repeated")
	assert.Equal(t, 1, metricRowsOfType(t, pool, "health.routers_online"),
		"the same fabric fact was written more than once")
}

// And the other direction, which is the half that would break the product if
// the gate were applied too widely: with no Redis there is no peer to
// coordinate with, so a single instance must still record its metrics.
func TestWithoutRedisTheSingleReplicaStillRecordsFabricMetrics(t *testing.T) {
	pool := openSweepPool(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS ziti_metrics;
		CREATE TABLE ziti_metrics (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			metric_type VARCHAR(100) NOT NULL,
			source VARCHAR(255) NOT NULL,
			value DOUBLE PRECISION NOT NULL,
			labels JSONB DEFAULT '{}',
			recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ziti_metrics;`) })

	zm := &ZitiManager{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}
	zm.recordFabricMetrics(ctx, nil, &FabricHealthStatus{SDKReady: true}, 1, nil)

	assert.Equal(t, 7, metricRows(t, pool),
		"a single instance with no Redis recorded nothing; the gate is supposed to be a no-op there")
}

func metricRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM ziti_metrics`).Scan(&n))
	return n
}

func metricRowsOfType(t *testing.T, pool *pgxpool.Pool, metric string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM ziti_metrics WHERE metric_type = $1`, metric).Scan(&n))
	return n
}
