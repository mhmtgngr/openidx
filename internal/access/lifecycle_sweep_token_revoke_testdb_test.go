package access

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/jitgrant"
	"github.com/openidx/openidx/internal/revocation"
)

// THE RECONCILE NET CAUGHT THE ACCESS AND LET THE CREDENTIAL THROUGH.
//
// This sweep exists for the disable paths that do NOT go through
// deprovisionUser -- SCIM deactivation, directory sync, a lifecycle policy, a
// direct database change -- and deprovisionUser is the one that cuts tokens. So
// for every path this sweep is the net for, the token was never cut: the
// elevation's row was removed and the access token in the user's browser kept
// naming the role, which the enforcement point resolves on every request.
//
// It was not a missing identity. EndAllForDisabledUsers SELECTs requester_id to
// do its work -- the users were in hand the whole time and simply were not
// passed back, because the function returned a count. A count cannot be
// revoked. (Its sibling EndAllForUser is HANDED the user, which is why its two
// callers already cut tokens and this one did not: the asymmetry hid the gap.)

func revokeSweepRedis(t *testing.T) (general, revoke *goredis.Client) {
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

// revokeSweepSchema is the narrow slice of the sweep this file is about: the
// elevation rows and the assignment tables they point at. The wider fixture in
// lifecycle_sweep_testdb_test.go seeds vault and Guacamole state too, which
// would only add ways for an unrelated statement to fail.
func revokeSweepSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS vault_checkouts, vault_access_grants, guacamole_sessions,
			access_requests, user_roles, group_memberships, user_application_assignments, users;
		CREATE TABLE users (id uuid primary key, enabled boolean NOT NULL DEFAULT true);
		CREATE TABLE vault_checkouts (
			id uuid primary key, principal_id uuid, status text NOT NULL, returned_at timestamptz);
		CREATE TABLE vault_access_grants (
			id uuid primary key, principal_type text NOT NULL, principal_id uuid, expires_at timestamptz);
		CREATE TABLE guacamole_sessions (
			id uuid primary key, user_id uuid, status text NOT NULL,
			guac_session_uuid text, ended_at timestamptz);
		CREATE TABLE access_requests (
			id uuid primary key, requester_id uuid, resource_type text, resource_id uuid,
			org_id uuid, status text NOT NULL, expires_at timestamptz, updated_at timestamptz);
		CREATE TABLE user_roles (user_id uuid, role_id uuid, org_id uuid);
		CREATE TABLE group_memberships (user_id uuid, group_id uuid, org_id uuid);
		CREATE TABLE user_application_assignments (user_id uuid, application_id uuid, org_id uuid);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS vault_checkouts,
			vault_access_grants, guacamole_sessions, access_requests, user_roles,
			group_memberships, user_application_assignments, users;`)
	})
}

func addUser(t *testing.T, pool *pgxpool.Pool, enabled bool) string {
	t.Helper()
	id := uuid.NewString()
	_, err := pool.Exec(context.Background(), `INSERT INTO users (id, enabled) VALUES ($1, $2)`, id, enabled)
	require.NoError(t, err)
	return id
}

// addElevation seeds a live fulfilled request plus the assignment row it
// granted, so ending it has something real to remove.
func addElevation(t *testing.T, pool *pgxpool.Pool, userID, org, rtype string) string {
	t.Helper()
	return addElevationExpiring(t, pool, userID, org, rtype, "1 day")
}

// addElevationExpiring lets a test fix the order the sweep will see, which is
// soonest expiry first.
func addElevationExpiring(t *testing.T, pool *pgxpool.Pool, userID, org, rtype, in string) string {
	t.Helper()
	ctx := context.Background()
	resID := uuid.NewString()
	_, err := pool.Exec(ctx,
		`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, org_id, status, expires_at)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'fulfilled', NOW() + $5::interval)`,
		userID, rtype, resID, org, in)
	require.NoError(t, err)

	assignment := map[string]string{
		"role":            `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`,
		"privileged_role": `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`,
		"group":           `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`,
		"application":     `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1,$2,$3)`,
	}[rtype]
	if assignment != "" {
		_, err = pool.Exec(ctx, assignment, userID, resID, org)
		require.NoError(t, err)
	}
	return resID
}

func sweepSvc(pool *pgxpool.Pool, general, revoke *goredis.Client) *Service {
	svc := &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop()}
	if general != nil {
		svc.redis = &database.RedisClient{Client: general, Revocation: revoke}
	}
	return svc
}

func cut(t *testing.T, r *goredis.Client, userID string) bool {
	t.Helper()
	err := r.Get(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Err()
	if err == goredis.Nil {
		return false
	}
	require.NoError(t, err)
	return true
}

// The whole point.
func TestTheLifecycleSweepCutsTheTokenOfADisabledUserWhoseElevationItEnds(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	general, revoke := revokeSweepRedis(t)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	disabled := addUser(t, pool, false)
	roleID := addElevation(t, pool, disabled, org, "role")

	sweepSvc(pool, general, revoke).runLifecycleEnforcement(ctx)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, disabled, roleID).Scan(&rows))
	require.Equal(t, 0, rows, "the elevation of a disabled user must be ended")
	require.True(t, cut(t, revoke, disabled),
		"the token still naming that role must be cut; this sweep is the net for every disable path that does not cut it itself")
}

// A marker in the general Redis is a marker nothing reads -- the exact shape
// this programme has already found once, under a different key.
func TestTheLifecycleSweepWritesTheMarkerToTheRevocationRedis(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	general, revoke := revokeSweepRedis(t)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	disabled := addUser(t, pool, false)
	addElevation(t, pool, disabled, org, "role")

	sweepSvc(pool, general, revoke).runLifecycleEnforcement(ctx)

	require.True(t, cut(t, revoke, disabled), "marker must be in the revocation database")
	require.False(t, cut(t, general, disabled), "marker must NOT be in the general database")
}

// An enabled user's live elevation is not the sweep's business, and cutting
// their session would be an outage caused by a reconcile pass.
func TestTheLifecycleSweepDoesNotCutAnEnabledUser(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	general, revoke := revokeSweepRedis(t)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	enabled := addUser(t, pool, true)
	roleID := addElevation(t, pool, enabled, org, "role")

	sweepSvc(pool, general, revoke).runLifecycleEnforcement(ctx)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, enabled, roleID).Scan(&rows))
	require.Equal(t, 1, rows, "an enabled user keeps their elevation")
	require.False(t, cut(t, revoke, enabled), "an enabled user must not be logged out by a reconcile sweep")
}

// An application assignment is in no claim: the row being gone IS the
// enforcement, so cutting here would be a re-login that changes no decision.
// Asserted so that changing the decision has to be deliberate.
func TestTheLifecycleSweepCutsNothingForAnApplicationElevation(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	general, revoke := revokeSweepRedis(t)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	disabled := addUser(t, pool, false)
	appID := addElevation(t, pool, disabled, org, "application")

	sweepSvc(pool, general, revoke).runLifecycleEnforcement(ctx)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_application_assignments WHERE user_id=$1 AND application_id=$2`, disabled, appID).Scan(&rows))
	require.Equal(t, 0, rows, "the assignment is still ended")
	require.False(t, cut(t, revoke, disabled), "no claim asserts an application grant")
}

// One user, three ended elevations, one cut. Measured on the returned list
// rather than on Redis, because a marker overwritten twice is indistinguishable
// from one written once -- the deduplication has to be visible where it
// happens.
func TestTheLifecycleSweepCutsAUserHoldingSeveralElevationsOnce(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	disabled := addUser(t, pool, false)
	addElevation(t, pool, disabled, org, "role")
	addElevation(t, pool, disabled, org, "privileged_role")
	addElevation(t, pool, disabled, org, "group")

	ended, cutTokensFor, err := jitgrant.EndAllForDisabledUsers(ctx, pool)
	require.NoError(t, err)
	require.Equal(t, int64(3), ended, "all three elevations end")
	require.Equal(t, []string{disabled}, cutTokensFor, "one user, cut once")
}

// A sweep that fails part way through has already removed real access. Whoever
// lost access must come back in the list, or a partial failure becomes the one
// case that severs access without severing the credential.
//
// Asserted as an invariant rather than against a fixed order: whatever order
// the rows come back in, every user whose assignment is actually gone must be
// in the list.
func TestTheLifecycleSweepReturnsEveryUserWhoseAccessItActuallyRemoved(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	// The failing row is INSERTED FIRST and expires LAST, so physical order and
	// expiry order disagree. Without the sweep's ORDER BY, Postgres hands back
	// insertion order, the unmapped type aborts the pass before anything is
	// removed, and this test would be measuring luck rather than the guarantee.
	bad := addUser(t, pool, false)
	addElevationExpiring(t, pool, bad, org, "widget", "2 days")
	good := addUser(t, pool, false)
	addElevationExpiring(t, pool, good, org, "role", "1 hour")

	_, cutTokensFor, err := jitgrant.EndAllForDisabledUsers(ctx, pool)
	require.Error(t, err, "an unmapped resource type must fail loud")

	var stillAssigned int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1`, good).Scan(&stillAssigned))
	require.Equal(t, 0, stillAssigned, "the first user's access was removed before the failure")
	require.Equal(t, []string{good}, cutTokensFor,
		"a user whose access the aborted sweep removed must still be cut; only they must be")
}

// An install with no Redis still reconciles. Refusing to run would leave the
// elevation live in the database as well as in the token, which is strictly
// worse than ending it and not cutting.
func TestTheLifecycleSweepStillEndsElevationsWithNoRedis(t *testing.T) {
	pool := openSweepPool(t)
	revokeSweepSchema(t, pool)
	ctx := orgctx.WithBypassRLS(context.Background())

	org := uuid.NewString()
	disabled := addUser(t, pool, false)
	roleID := addElevation(t, pool, disabled, org, "role")

	sweepSvc(pool, nil, nil).runLifecycleEnforcement(ctx)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, disabled, roleID).Scan(&rows))
	require.Equal(t, 0, rows, "the sweep must still end elevations without Redis")
}
