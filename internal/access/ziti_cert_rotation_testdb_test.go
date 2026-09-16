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
// WHAT THE OLD VERSION OF THIS TEST MEASURED, AND WHY IT WAS REPLACED.
//
// It raced two replicas at one certificate and asserted that exactly one stood
// down. That passed for weeks and then failed on main; measured here, it fails
// 6 times in 20. The cause is not the environment and not a slow runner.
//
// RotateCertificate claims with `UPDATE ... SET status='rotating' WHERE
// id=$1 AND status='active'`, and the claim is exclusive. But the CA path --
// the one this test uses, because it completes without a Ziti controller --
// refuses the certificate and calls revertCertStatus, putting the row straight
// back to 'active'. The whole claim lasts microseconds. Whether the second
// replica stands down depends on whether its UPDATE lands inside that window,
// so "exactly one of two concurrent replicas stands down" was never a property
// of the code: it was a property of the scheduler, and the test reported on the
// scheduler.
//
// What IS true is asserted below, in three pieces: a held claim excludes
// everyone else (deterministic), a released claim may be taken again (which is
// the reason the old assertion could not hold), and under ANY interleaving
// every racer ends in one of exactly two legitimate outcomes.

func setupRotationCert(t *testing.T, certType string) (string, string, *pgxpool.Pool) {
	t.Helper()
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
		 VALUES ($1, 'edge-router-1', $2, 'active', $3, true)`,
		cert, certType, time.Now().Add(72*time.Hour))
	require.NoError(t, err)
	return dsn, cert, pool
}

func rotationManager(t *testing.T, dsn string) *ZitiManager {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &ZitiManager{
		logger: zap.NewNop(),
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
	}
}

// THE INVARIANT THE MONITOR RESTS ON, measured without a race: while one
// replica holds the claim, every other replica stands down -- and says so with
// errRotationNotClaimed rather than with a failure, because the monitor's log
// level is chosen from exactly that distinction.
func TestAHeldRotationClaimExcludesEveryOtherReplica(t *testing.T) {
	dsn, cert, pool := setupRotationCert(t, "ca")
	ctx := context.Background()

	// Another replica holds it. This is the state the claim UPDATE creates,
	// written directly so the window is not a matter of timing.
	_, err := pool.Exec(ctx, `UPDATE ziti_certificates SET status = 'rotating' WHERE id = $1`, cert)
	require.NoError(t, err)

	err = rotationManager(t, dsn).RotateCertificate(ctx, cert)

	require.Error(t, err, "a replica claimed a rotation another replica is already holding")
	require.ErrorIs(t, err, errRotationNotClaimed,
		"standing down must be distinguishable from failing: the expiry monitor logs one at Debug and the "+
			"other at Error, and an operator who sees a security-relevant rotation 'fail' every hour learns "+
			"to skip the line")
}

// AND THE FACT THAT MADE THE OLD ASSERTION IMPOSSIBLE. The CA path refuses the
// certificate and hands the claim back, so the row is active again and the next
// replica along takes it -- correctly. Two claims in sequence are two no-ops,
// not a duplicated rotation, and this is why "exactly one of two stands down"
// could never hold.
func TestAReleasedRotationClaimIsTakenAgain(t *testing.T) {
	dsn, cert, pool := setupRotationCert(t, "ca")
	ctx := context.Background()
	zm := rotationManager(t, dsn)

	first := zm.RotateCertificate(ctx, cert)
	require.Error(t, first, "a CA certificate cannot be auto-rotated and must say so")
	require.NotErrorIs(t, first, errRotationNotClaimed, "the first replica DID claim it; the refusal is about the cert type")

	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM ziti_certificates WHERE id = $1`, cert).Scan(&status))
	require.Equal(t, "active", status,
		"the refusal must hand the claim back; a certificate parked in 'rotating' is one nobody will ever renew")

	second := zm.RotateCertificate(ctx, cert)
	require.Error(t, second)
	require.NotErrorIs(t, second, errRotationNotClaimed,
		"with the claim released, the next replica takes it and refuses it for the same reason -- which is the "+
			"whole reason a concurrent test cannot assert that exactly one replica stands down")
}

// THE CONCURRENT CASE, asserting what is true under EVERY interleaving rather
// than what happens to be true under most of them. Each racer either stood down
// or took the claim and refused the CA certificate; nothing else is a legitimate
// outcome, and the row is left active either way.
func TestConcurrentReplicasEndInOneOfTwoLegitimateOutcomes(t *testing.T) {
	dsn, cert, pool := setupRotationCert(t, "ca")
	ctx := context.Background()

	const replicas = 2
	errsOut := make([]error, replicas)
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		zm := rotationManager(t, dsn)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errsOut[i] = zm.RotateCertificate(ctx, cert)
		}(i)
	}
	wg.Wait()

	for i, err := range errsOut {
		require.Error(t, err, "replica %d reported a successful rotation of a CA certificate, which cannot be auto-rotated", i)
		if errors.Is(err, errRotationNotClaimed) {
			continue // stood down: another replica held the claim
		}
		assert.Contains(t, err.Error(), "CA certificates cannot be auto-rotated",
			"replica %d neither stood down nor refused the CA certificate; it failed some third way: %v", i, err)
		assert.NotContains(t, err.Error(), "not claimed",
			"a real rotation failure is being reported as a stand-down")
	}

	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM ziti_certificates WHERE id = $1`, cert).Scan(&status))
	assert.Equal(t, "active", status,
		"whoever won, the claim must be back: a certificate left in 'rotating' is one no replica will ever pick up again")
}
