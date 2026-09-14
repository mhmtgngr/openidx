package access

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE POSTURE EXPIRY SWEEP IS THE SECOND ENTRY IN THE CENSUS TO CLAIM
// `idempotent`, and the first one taught that the claim is worth measuring
// rather than reading.
//
// It is one statement -- DELETE FROM device_posture_results WHERE expires_at <
// NOW() -- so the repetition half is close to free: the rows a second replica
// would delete are already gone. What is NOT obvious, and is what this file
// actually measures, is the second half of the claim: that the sweep DECIDES
// nothing.
//
// The worry is specific. device_posture_results feeds the access proxy's
// posture enforcement, and a sweep that deletes a device's posture data could
// plausibly be the thing that moves that device from allowed to denied -- which
// would make it a transition, running once per replica, on a Zero Trust
// enforcement path. It is not, and the reason is in EvaluateIdentityPosture: a
// check whose result has EXPIRED fails, and a check with NO result at all fails
// the same way. Deleting an already-expired row therefore cannot change any
// access decision; it reclaims storage from rows that had already stopped
// counting.
//
// So the test asserts the decision itself, per check, across the sweep -- not
// the row count. A row count would pass for a sweep that deleted live results
// too, and that sweep would be a silent denial of service against every device
// whose posture was still valid.

// seedPosture builds only the two tables and the columns the expiry sweep and
// the evaluator read. The real schema carries considerably more; a sweep test
// that needed all of it would be a migration test under another name.
func seedPosture(t *testing.T, pool *pgxpool.Pool) (*ZitiManager, context.Context, string, map[string]string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS device_posture_results, posture_checks;
		CREATE TABLE posture_checks (
			id uuid primary key, ziti_id text NOT NULL DEFAULT '', name text NOT NULL,
			check_type text NOT NULL, parameters jsonb, enabled boolean NOT NULL DEFAULT true,
			severity text NOT NULL DEFAULT 'high', remediation_hint text NOT NULL DEFAULT '',
			platforms jsonb, created_at timestamptz NOT NULL DEFAULT NOW(),
			updated_at timestamptz NOT NULL DEFAULT NOW(), org_id uuid NOT NULL);
		CREATE TABLE device_posture_results (
			id uuid primary key, identity_id uuid NOT NULL, check_id uuid NOT NULL,
			passed boolean NOT NULL, details jsonb, checked_at timestamptz NOT NULL DEFAULT NOW(),
			expires_at timestamptz, org_id uuid NOT NULL);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS device_posture_results, posture_checks;`)
	})

	org := uuid.NewString()
	identity := uuid.NewString()
	fresh, stale := uuid.NewString(), uuid.NewString()

	// One statement per Exec: pgx prepares parameterised statements, and a
	// prepared statement carries exactly one command.
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO posture_checks (id, name, check_type, enabled, org_id)
			VALUES ($1, 'disk encryption', 'os', true, $3), ($2, 'edr running', 'process', true, $3)`,
			[]any{fresh, stale, org}},
		// The fresh result is valid for another day; the stale one expired an
		// hour ago and is what the sweep is entitled to remove.
		{`INSERT INTO device_posture_results (id, identity_id, check_id, passed, expires_at, org_id)
			VALUES (gen_random_uuid(), $1, $2, true, NOW() + interval '1 day', $4),
			       (gen_random_uuid(), $1, $3, true, NOW() - interval '1 hour', $4)`,
			[]any{identity, fresh, stale, org}},
	} {
		_, err = pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err, seed.sql)
	}

	zm := &ZitiManager{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}
	return zm, orgctx.With(ctx, orgctx.Org{ID: org, Slug: "posture-sweep"}), identity,
		map[string]string{fresh: "fresh", stale: "stale"}
}

// postureDecision is what the enforcement path would conclude: pass or fail,
// per check, by the check's name rather than its uuid so a failure names the
// check a human can find.
func postureDecision(t *testing.T, zm *ZitiManager, ctx context.Context, identity string, names map[string]string) (bool, map[string]bool) {
	t.Helper()
	overall, results, err := zm.EvaluateIdentityPosture(ctx, identity)
	require.NoError(t, err)
	per := map[string]bool{}
	for _, r := range results {
		per[names[r.CheckID]] = r.Passed
	}
	return overall, per
}

func postureRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_posture_results`).Scan(&n))
	return n
}

// The sweep removes expired rows and leaves every access decision exactly where
// it found it. That is the whole content of the census entry's "it decides
// nothing", and it is the half that would make a per-replica repeat matter.
func TestThePostureExpirySweepChangesNoAccessDecision(t *testing.T) {
	pool := openSweepPool(t)
	zm, ctx, identity, names := seedPosture(t, pool)

	overallBefore, perBefore := postureDecision(t, zm, ctx, identity, names)
	assert.False(t, overallBefore, "an expired result must already fail before the sweep touches anything")
	assert.Equal(t, map[string]bool{"fresh": true, "stale": false}, perBefore,
		"the expired check fails and the live one passes -- this is the state the sweep must not move")
	require.Equal(t, 2, postureRows(t, pool))

	zm.cleanExpiredPostureResults(ctx)

	assert.Equal(t, 1, postureRows(t, pool), "the sweep deletes the expired row and only that one")
	overallAfter, perAfter := postureDecision(t, zm, ctx, identity, names)
	assert.Equal(t, overallBefore, overallAfter)
	assert.Equal(t, perBefore, perAfter,
		"deleting an already-expired result changed an access decision; the sweep is a transition after all "+
			"and running it once per replica is no longer free")
}

// And the claim the census actually rests on: any number of replicas, at once.
// A DELETE cannot apply twice, but a sweep that also read something, or that
// deleted by a predicate evaluated in Go, could still race -- so this runs the
// real function eight times concurrently and requires the result to be both
// correct and SETTLED: a further pass afterwards changes nothing, so nothing
// was left half-applied for a later tick.
func TestEightConcurrentPostureExpirySweepsConvergeTheSameWay(t *testing.T) {
	pool := openSweepPool(t)
	zm, ctx, identity, names := seedPosture(t, pool)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zm.cleanExpiredPostureResults(ctx)
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, postureRows(t, pool),
		"eight concurrent sweeps must leave what one leaves: the live result, and nothing else deleted")
	overall, per := postureDecision(t, zm, ctx, identity, names)
	assert.False(t, overall)
	assert.Equal(t, map[string]bool{"fresh": true, "stale": false}, per)

	zm.cleanExpiredPostureResults(ctx)
	assert.Equal(t, 1, postureRows(t, pool), "a pass after the concurrent run still changes nothing -- settled")
}
