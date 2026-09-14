package access

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// THE USER-SYNC POLLER IS CHECK-THEN-ACT ACROSS TWO SYSTEMS, AND NOTHING
// CLAIMED THE USER.
//
// runAutoSync selects up to ten users with no ziti_identities row, and every
// replica selects the same ten. At the 30-second tick two replicas both find a
// user unsynced, both ask the controller for an identity, and both try to
// persist it.
//
// Nothing corrupts, and the reason is two unique constraints on the same name,
// one in each system: the controller rejects a duplicate identity name, and
// ziti_identities.name is UNIQUE with name = the user id. That half is READ
// rather than measured -- there is no Ziti controller in reach, the same
// honesty the census applies to ziti_reconciler.go.
//
// THE DATABASE HALF IS MEASURED HERE, and it is where the visible defect was.
// The losing insert raised a unique violation and the poller reported
// "Auto-sync failed for user" -- once per losing replica, per tick, for a user
// that had just been synced. An operator watching for sync failures saw one
// every thirty seconds that meant nothing.
func TestOnlyOneReplicaCreatesAUsersZitiIdentity(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the Ziti identity claim test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// Only the columns the insert writes, and the constraint that makes the
	// race safe: name is UNIQUE and the sync sets it to the user id.
	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS ziti_identities;
		CREATE TABLE ziti_identities (
			id uuid primary key DEFAULT gen_random_uuid(),
			ziti_id text UNIQUE NOT NULL,
			name text UNIQUE NOT NULL,
			identity_type text,
			user_id uuid,
			enrollment_jwt text,
			attributes jsonb,
			group_attrs_synced_at timestamptz,
			org_id uuid);`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ziti_identities;`) })

	user := uuid.NewString()
	org := uuid.NewString()

	// Two replicas, each with its own pool, each having been handed a
	// DIFFERENT controller identity id -- which is what actually happens when
	// the loser adopts the winner's identity a moment later.
	const replicas = 2
	created := make([]bool, replicas)
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		replicaPool, perr := pgxpool.New(ctx, dsn)
		require.NoError(t, perr)
		t.Cleanup(replicaPool.Close)
		zm := &ZitiManager{
			logger: zap.NewNop(),
			db:     &database.PostgresDB{Pool: database.NewScopedPool(replicaPool)},
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			created[i], errs[i] = zm.persistZitiIdentity(
				ctx, uuid.NewString(), user, "jwt-from-replica", []byte(`["group:eng"]`), org)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "replica %d reported a failure for a user that was synced", i)
	}
	claims := 0
	for _, c := range created {
		if c {
			claims++
		}
	}
	assert.Equal(t, 1, claims, "both replicas reported creating the same user's identity")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM ziti_identities WHERE user_id = $1`, user).Scan(&rows))
	assert.Equal(t, 1, rows, "a user ended up with more than one Ziti identity row")

	// And the row that survived carries an enrolment token: a user whose row
	// was written by the loser would have the adopted identity's empty JWT and
	// could never enrol a device.
	var jwt string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT enrollment_jwt FROM ziti_identities WHERE user_id = $1`, user).Scan(&jwt))
	assert.Equal(t, "jwt-from-replica", jwt)
}
