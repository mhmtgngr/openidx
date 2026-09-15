package identity

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/revocation"
)

// A TIME-BOUND ROLE HAS TO STOP WORKING WHEN ITS TIME IS UP.
//
// `expires_at` on user_roles is this product's temporary elevation: an admin
// until 15:00. The sweep deletes the row at 15:00 -- and the enforcement point
// has never read that row. PermissionResolver takes the caller's roles from the
// JWT `roles` claim, so the token minted at 14:00 keeps saying "admin".
//
// These run against a real PostgreSQL and a real Redis because the question is
// what one process leaves behind for another to read, and the answer has to
// come from the key the ENFORCEMENT POINT reads, not from a mock of it.

// openExpiryPool builds the smallest user_roles a sweep needs, in a schema of
// its own so it cannot see or damage anything else in the database.
func openExpiryPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the role-expiry sweep tests (they need a real Postgres)")
	}
	schema := "expiry_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	bootstrap, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	_, err = bootstrap.Exec(context.Background(), `CREATE SCHEMA `+schema)
	bootstrap.Close()
	require.NoError(t, err, "the test DSN must be allowed to create a schema")

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		pool.Close()
		if drop, derr := pgxpool.New(context.Background(), dsn); derr == nil {
			_, _ = drop.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			drop.Close()
		}
	})

	_, err = pool.Exec(context.Background(), `
		CREATE TABLE user_roles (
			user_id uuid NOT NULL, role_id uuid NOT NULL, org_id uuid NOT NULL,
			assigned_by uuid, assigned_at timestamptz DEFAULT NOW(),
			expires_at timestamptz,
			PRIMARY KEY (user_id, role_id))`)
	require.NoError(t, err)
	return pool
}

// TWO REDIS DATABASES, ON PURPOSE. The roles were split into three instances
// and the enforcement point reads the REVOCATION one; a single client would let
// a marker written to the wrong role pass unnoticed, which is the very defect
// internal/revocation exists to prevent.
func openExpiryRedis(t *testing.T) (general, revoke *goredis.Client) {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	general = goredis.NewClient(&goredis.Options{Addr: addr, DB: 10})
	if err := general.Ping(context.Background()).Err(); err != nil {
		t.Skipf("no Redis at %s: %v", addr, err)
	}
	revoke = goredis.NewClient(&goredis.Options{Addr: addr, DB: 11})
	require.NoError(t, revoke.Ping(context.Background()).Err())
	require.NoError(t, general.FlushDB(context.Background()).Err())
	require.NoError(t, revoke.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = general.Close(); _ = revoke.Close() })
	return general, revoke
}

func expirySvc(t *testing.T, pool *pgxpool.Pool, general, revoke *goredis.Client) *Service {
	t.Helper()
	return &Service{
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
		redis:  &database.RedisClient{Client: general, Revocation: revoke},
		logger: zap.NewNop(),
	}
}

func seedAssignment(t *testing.T, pool *pgxpool.Pool, userID string, expiresAt *time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`,
		userID, uuid.NewString(), uuid.NewString(), expiresAt)
	require.NoError(t, err)
}

// The whole point, in one test: the row goes AND the token is cut.
func TestAnExpiredElevationRevokesTheTokenStillCarryingIt(t *testing.T) {
	pool := openExpiryPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)

	userID := uuid.NewString()
	past := time.Now().Add(-time.Minute)
	seedAssignment(t, pool, userID, &past)

	svc.cleanupExpiredRoles(context.Background())

	var left int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, userID).Scan(&left))
	require.Equal(t, 0, left, "the expired assignment was not removed")

	// Read it back from the key the enforcement point reads, not from a
	// convenience helper: that is the only thing that proves the marker landed
	// somewhere that will actually be consulted.
	got, err := revoke.Get(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err,
		"the elevation expired and nothing revoked the tokens still carrying it: "+
			"the role list comes from the JWT, so the access token minted before the "+
			"expiry keeps naming that role until it expires on its own")
	require.NotEmpty(t, got)
}

// A marker in the wrong Redis is a marker with no reader — the defect
// internal/revocation was created to fix. This is what makes the split real.
func TestTheExpirySweepWritesToTheRevocationRedisNotTheGeneralOne(t *testing.T) {
	pool := openExpiryPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)

	userID := uuid.NewString()
	past := time.Now().Add(-time.Minute)
	seedAssignment(t, pool, userID, &past)

	svc.cleanupExpiredRoles(context.Background())

	key := revocation.UserTokensRevokedAtKey(userID)
	n, err := general.Exists(context.Background(), key).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), n,
		"the revocation marker was written to the GENERAL Redis, where /oauth/userinfo never looks")

	n, err = revoke.Exists(context.Background(), key).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "the marker is missing from the revocation Redis")
}

// An assignment that has NOT expired must be left alone in both stores. A sweep
// that revokes everybody it looks at would cut live sessions on every tick.
func TestAnUnexpiredElevationIsNotTouched(t *testing.T) {
	pool := openExpiryPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)

	userID := uuid.NewString()
	future := time.Now().Add(time.Hour)
	seedAssignment(t, pool, userID, &future)

	svc.cleanupExpiredRoles(context.Background())

	var left int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, userID).Scan(&left))
	require.Equal(t, 1, left, "an assignment that has not expired was removed")

	n, err := revoke.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), n, "a live elevation had its tokens revoked")
}

// A permanent assignment (expires_at IS NULL) is not an expiry at all.
func TestAPermanentAssignmentIsNeverSweptOrRevoked(t *testing.T) {
	pool := openExpiryPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)

	userID := uuid.NewString()
	seedAssignment(t, pool, userID, nil)

	svc.cleanupExpiredRoles(context.Background())

	var left int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, userID).Scan(&left))
	require.Equal(t, 1, left, "a permanent assignment was swept")

	n, err := revoke.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), n, "a permanent assignment had its tokens revoked")
}

// One user, several elevations expiring on the same tick: the marker is per
// user, so it is written once and the run does not depend on the row count.
func TestSeveralElevationsExpiringTogetherRevokeTheUserOnce(t *testing.T) {
	pool := openExpiryPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)

	userID := uuid.NewString()
	past := time.Now().Add(-time.Minute)
	seedAssignment(t, pool, userID, &past)
	seedAssignment(t, pool, userID, &past)
	seedAssignment(t, pool, userID, &past)

	svc.cleanupExpiredRoles(context.Background())

	var left int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, userID).Scan(&left))
	require.Equal(t, 0, left)

	n, err := revoke.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
}

// The sweep runs in a deployment with no Redis at all. It must still remove the
// expired assignments -- refusing to sweep would leave the grant in place, which
// is worse than removing it and saying the token was not cut.
func TestTheSweepStillRemovesExpiredAssignmentsWithNoRedis(t *testing.T) {
	pool := openExpiryPool(t)
	svc := &Service{
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
		logger: zap.NewNop(),
	}

	userID := uuid.NewString()
	past := time.Now().Add(-time.Minute)
	seedAssignment(t, pool, userID, &past)

	svc.cleanupExpiredRoles(context.Background())

	var left int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, userID).Scan(&left))
	require.Equal(t, 0, left, "the sweep refused to run without Redis and left the elevation in place")
}
