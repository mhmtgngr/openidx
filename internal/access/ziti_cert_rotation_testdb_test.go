package access

import (
	"context"
	"errors"
	"os"
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

// THE ROTATION WAS ALWAYS CLAIMED; LOSING THE CLAIM WAS REPORTED AS A FAILURE.
//
// The certificate expiry monitor runs in every replica on the same hourly tick
// and every replica lists the same expiring certificates. RotateCertificate
// opens with `UPDATE ... SET status='rotating' WHERE id=$1 AND status='active'`
// -- a real claim, so exactly one replica rotates and the others stand down.
// That part was right.
//
// What was wrong is what the others then said: "Auto-rotation failed for
// certificate", at Error, about a certificate that was being rotated correctly
// by another replica. A certificate rotation is a security-relevant operation,
// and an operator who watches it fail every hour for a rotation that in fact
// succeeded learns to skip the line -- the same defect the Ziti user-sync
// poller had, one alarm at a time.
func TestOnlyOneReplicaClaimsACertificateRotation(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the certificate rotation claim test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS ziti_certificates;
		CREATE TABLE ziti_certificates (
			id uuid primary key, name text NOT NULL, cert_type text NOT NULL,
			associated_identity_id uuid, status text NOT NULL,
			not_after timestamptz, auto_renew boolean DEFAULT false,
			renewal_threshold_days int DEFAULT 30,
			updated_at timestamptz);`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ziti_certificates;`) })

	cert := uuid.NewString()
	_, err = pool.Exec(ctx,
		`INSERT INTO ziti_certificates (id, name, cert_type, status, not_after, auto_renew)
		 VALUES ($1, 'edge-router-1', 'ca', 'active', $2, true)`,
		cert, time.Now().Add(72*time.Hour))
	require.NoError(t, err)

	// 'ca' on purpose: the rotation refuses CA certificates and reverts the
	// status, so the winner's path completes without a Ziti controller. What
	// this test is about is who gets to start.
	const replicas = 2
	errsOut := make([]error, replicas)
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
			errsOut[i] = zm.RotateCertificate(ctx, cert)
		}(i)
	}
	wg.Wait()

	standDowns := 0
	for _, err := range errsOut {
		if errors.Is(err, errRotationNotClaimed) {
			standDowns++
		}
	}
	assert.Equal(t, 1, standDowns,
		"expected exactly one replica to stand down; a rotation claimed by two replicas, or by neither, "+
			"is either a duplicated rotation or a certificate nobody renews")

	// The stand-down must be distinguishable from a real failure, because the
	// monitor's log level depends on telling them apart.
	for _, err := range errsOut {
		if err != nil && !errors.Is(err, errRotationNotClaimed) {
			assert.NotContains(t, err.Error(), "not claimed",
				"a real rotation failure is being reported as a stand-down")
		}
	}
}
