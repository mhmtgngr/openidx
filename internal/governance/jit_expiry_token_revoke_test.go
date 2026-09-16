package governance

import (
	"context"
	"os"
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
)

// The JIT expiry sweep is the deadline itself: "admin until 15:00" is enforced
// by this code and nothing else. It removed the assignment row and stopped, so
// the token minted at 14:00 kept naming the role and the enforcement point kept
// resolving that role's permissions -- the elevation outlived the expiry that
// defines it.
//
// Measured against a real Postgres and a real Redis, with the general and the
// revocation roles bound to SEPARATE Redis databases so a marker written to the
// wrong one is visible rather than masked, and read back through the key the
// enforcement point actually reads.

func jitRedis(t *testing.T) (general, revoke *goredis.Client) {
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

// jitExpirySchema builds only what the sweep touches. Each test gets the tables
// fresh, because setupTestDB resets the schema per call.
func jitExpirySchema(t *testing.T, db *database.PostgresDB, ctx context.Context) {
	t.Helper()
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY, requester_id UUID, resource_type VARCHAR(50),
			resource_id UUID, resource_name VARCHAR(255), org_id UUID,
			status VARCHAR(30), expires_at TIMESTAMPTZ, updated_at TIMESTAMPTZ DEFAULT now());
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
		CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID);
		CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID);
		CREATE TABLE network_revocation_queue (org_id UUID, user_id UUID, reason TEXT);
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY, event_type VARCHAR(50), category VARCHAR(50), action VARCHAR(100),
			outcome VARCHAR(20), actor_id UUID, actor_ip VARCHAR(45), target_id UUID,
			target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ, org_id UUID);
		CREATE TABLE temp_access_links (status VARCHAR(20), expires_at TIMESTAMPTZ);
	`)
	require.NoError(t, err)
}

func jitSvc(t *testing.T, db *database.PostgresDB, general, revoke *goredis.Client) *Service {
	t.Helper()
	return &Service{
		db:     db,
		redis:  &database.RedisClient{Client: general, Revocation: revoke},
		logger: zap.NewNop(),
	}
}

const (
	jitOrg   = "00000000-0000-0000-0000-0000000000a1"
	jitUser  = "00000000-0000-0000-0000-0000000000b1"
	jitRole  = "00000000-0000-0000-0000-0000000000c1"
	jitGroup = "00000000-0000-0000-0000-0000000000c2"
	jitApp   = "00000000-0000-0000-0000-0000000000c3"
)

func seedExpired(t *testing.T, db *database.PostgresDB, ctx context.Context, reqID, rtype, resID string) {
	t.Helper()
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, org_id, status, expires_at)
		 VALUES ($1, $2, $3, $4, 'r', $5, 'fulfilled', NOW() - INTERVAL '1 hour')`,
		reqID, jitUser, rtype, resID, jitOrg)
	require.NoError(t, err)
}

func markerFor(t *testing.T, r *goredis.Client, userID string) (string, bool) {
	t.Helper()
	v, err := r.Get(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	if err == goredis.Nil {
		return "", false
	}
	require.NoError(t, err)
	return v, true
}

// The whole point: the elevation ends in the database AND in the token.
func TestAnExpiredJITRoleCutsTheTokenStillNamingIt(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)
	general, revoke := jitRedis(t)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "role", jitRole)
	_, err := db.Pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, jitUser, jitRole, jitOrg)
	require.NoError(t, err)

	jitSvc(t, db, general, revoke).revokeExpiredJITAccess(ctx)

	var rows int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, jitUser, jitRole).Scan(&rows))
	require.Equal(t, 0, rows, "the expired assignment must be gone")

	_, ok := markerFor(t, revoke, jitUser)
	require.True(t, ok, "an expired elevation must cut the token that still names the role")
}

// The marker has to land in the database the enforcement point reads. Writing
// it to the general Redis would pass any test that only asks "was something
// written"; these two assertions are why the roles are on separate DBs.
func TestTheJITSweepWritesToTheRevocationRedisNotTheGeneralOne(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)
	general, revoke := jitRedis(t)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "role", jitRole)
	_, err := db.Pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, jitUser, jitRole, jitOrg)
	require.NoError(t, err)

	jitSvc(t, db, general, revoke).revokeExpiredJITAccess(ctx)

	_, inRevocation := markerFor(t, revoke, jitUser)
	require.True(t, inRevocation, "marker must be in the revocation database")
	_, inGeneral := markerFor(t, general, jitUser)
	require.False(t, inGeneral, "marker must NOT be in the general database")
}

// A group membership is a claim on the token too, so ending one cuts it.
func TestAnExpiredJITGroupAlsoCutsTheToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)
	general, revoke := jitRedis(t)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "group", jitGroup)
	_, err := db.Pool.Exec(ctx, `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, jitUser, jitGroup, jitOrg)
	require.NoError(t, err)

	jitSvc(t, db, general, revoke).revokeExpiredJITAccess(ctx)

	_, ok := markerFor(t, revoke, jitUser)
	require.True(t, ok, "an expired group elevation must cut the token that still asserts it")
}

// An application assignment is in no claim -- access is read from the table
// when it is used, so the row being gone IS the enforcement. Cutting here would
// force a re-login that changes no decision. This asserts the DECISION, so that
// changing it has to be deliberate.
func TestAnExpiredJITApplicationDoesNotCutTheToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)
	general, revoke := jitRedis(t)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "application", jitApp)
	_, err := db.Pool.Exec(ctx, `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1,$2,$3)`, jitUser, jitApp, jitOrg)
	require.NoError(t, err)

	jitSvc(t, db, general, revoke).revokeExpiredJITAccess(ctx)

	var rows int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_application_assignments WHERE user_id=$1`, jitUser).Scan(&rows))
	require.Equal(t, 0, rows, "the assignment is still revoked")

	_, ok := markerFor(t, revoke, jitUser)
	require.False(t, ok, "an application grant is in no claim; cutting the token would change no decision")
}

// A revocation that failed to remove the access must not cut the token either:
// the sweep skips the row and retries next tick, and a marker written for a
// user whose access is still live is a re-login that fixes nothing while
// reading, in the log, as if the deadline had been enforced.
func TestAnUnmappedTypeCutsNothingAndStaysFulfilled(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)
	general, revoke := jitRedis(t)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "widget", jitRole)

	jitSvc(t, db, general, revoke).revokeExpiredJITAccess(ctx)

	var st string
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT status FROM access_requests WHERE id=$1`, "a0000000-0000-0000-0000-000000000001").Scan(&st))
	require.Equal(t, "fulfilled", st, "an unmapped type must fail loud, not record a false success")

	_, ok := markerFor(t, revoke, jitUser)
	require.False(t, ok, "no access was removed, so nothing should be cut")
}

// An install with no Redis must still sweep. Refusing to run would leave the
// elevation in place, which is worse than removing it and not cutting the
// token: the first leaves access live in the database AND the token, the
// second only in the token.
func TestTheJITSweepStillExpiresGrantsWithNoRedis(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	jitExpirySchema(t, db, ctx)

	seedExpired(t, db, ctx, "a0000000-0000-0000-0000-000000000001", "role", jitRole)
	_, err := db.Pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, jitUser, jitRole, jitOrg)
	require.NoError(t, err)

	(&Service{db: db, logger: zap.NewNop()}).revokeExpiredJITAccess(ctx)

	var rows int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1`, jitUser).Scan(&rows))
	require.Equal(t, 0, rows, "the sweep must still remove expired access without Redis")
}
