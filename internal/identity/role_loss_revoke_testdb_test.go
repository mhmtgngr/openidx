package identity

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
)

// THREE ADMIN-PLANE PATHS TAKE A ROLE AWAY, AND NONE OF THEM CUT THE TOKEN.
//
// Each is reached from an HTTP handler an administrator drives directly
// (service.go:4224, :4301, :4339), and none of them disables the account — so
// none is covered by the sever work, which only revokes where the account is
// being cut off entirely.
//
// The enforcement point reads the caller's roles from the JWT `roles` claim, so
// removing the row changes nothing for a session already holding a token. The
// administrator sees 200 and an audit line saying success.

// roleLossPool builds the tables these three paths touch.
func roleLossPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := openExpiryPool(t) // same schema-isolated helper; user_roles already there
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE roles (
			id uuid PRIMARY KEY, name varchar(255) NOT NULL, description text,
			is_composite boolean DEFAULT false, org_id uuid NOT NULL,
			created_at timestamptz DEFAULT NOW(), updated_at timestamptz DEFAULT NOW());
		CREATE TABLE composite_roles (
			parent_role_id uuid NOT NULL, child_role_id uuid NOT NULL, org_id uuid NOT NULL);
		CREATE TABLE audit_events (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id uuid, timestamp timestamptz DEFAULT NOW(),
			event_type text, category text, action text, outcome text,
			actor_id text, actor_type text, actor_ip text,
			target_id text, target_type text, resource_id text, details jsonb)`)
	require.NoError(t, err)
	return pool
}

func roleLossFixture(t *testing.T) (*Service, *pgxpool.Pool, *goredis.Client, *goredis.Client, context.Context, string) {
	t.Helper()
	pool := roleLossPool(t)
	general, revoke := openExpiryRedis(t)
	svc := expirySvc(t, pool, general, revoke)
	org := uuid.NewString()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	return svc, pool, general, revoke, ctx, org
}

func seedRole(t *testing.T, pool *pgxpool.Pool, org, name string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO roles (id, name, org_id) VALUES ($1::uuid, $2, $3::uuid)`, id, name, org)
	require.NoError(t, err)
	return id
}

func seedHeld(t *testing.T, pool *pgxpool.Pool, org, userID, roleID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		userID, roleID, org)
	require.NoError(t, err)
}

func revoked(t *testing.T, rdb *goredis.Client, userID string) bool {
	t.Helper()
	n, err := rdb.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	return n == 1
}

func TestRemovingARoleRevokesTheTokenThatStillNamesIt(t *testing.T) {
	svc, pool, general, revoke, ctx, org := roleLossFixture(t)
	user, role := uuid.NewString(), seedRole(t, pool, org, "ops")
	seedHeld(t, pool, org, user, role)

	require.NoError(t, svc.RemoveUserRole(ctx, user, role))

	require.True(t, revoked(t, revoke, user),
		"the role was removed and the token naming it was not cut: the role list comes "+
			"from the JWT, so the access token keeps granting it until it expires")
	require.False(t, revoked(t, general, user),
		"the marker went to the general Redis, where the enforcement point never looks")
}

// Deleting a role takes it from EVERY holder, and it cuts by predicate — so
// without RETURNING there is nobody to revoke.
func TestDeletingARoleRevokesEveryHolder(t *testing.T) {
	svc, pool, _, revoke, ctx, org := roleLossFixture(t)
	role := seedRole(t, pool, org, "auditors")
	a, b, c := uuid.NewString(), uuid.NewString(), uuid.NewString()
	seedHeld(t, pool, org, a, role)
	seedHeld(t, pool, org, b, role)
	seedHeld(t, pool, org, c, role)

	require.NoError(t, svc.DeleteRole(ctx, role))

	for _, u := range []string{a, b, c} {
		require.True(t, revoked(t, revoke, u),
			"a holder of the deleted role kept a token naming it; the delete cuts by "+
				"predicate, so without RETURNING there are no identities to revoke")
	}
}

// A replacement that only ADDS is a grant. Cutting there would end a live
// session for no security gain at all.
func TestAddingARoleDoesNotCutTheSession(t *testing.T) {
	svc, pool, _, revoke, ctx, org := roleLossFixture(t)
	user := uuid.NewString()
	kept := seedRole(t, pool, org, "reader")
	added := seedRole(t, pool, org, "writer")
	seedHeld(t, pool, org, user, kept)

	require.NoError(t, svc.UpdateUserRoles(ctx, user, []string{kept, added}, "admin"))

	require.False(t, revoked(t, revoke, user),
		"a pure grant ended the user's session; only the revocation half of a "+
			"replacement needs the token cut")
}

// The same call, the other direction: anything lost means the token must go.
func TestAReplacementThatDropsARoleRevokes(t *testing.T) {
	svc, pool, _, revoke, ctx, org := roleLossFixture(t)
	user := uuid.NewString()
	kept := seedRole(t, pool, org, "reader")
	dropped := seedRole(t, pool, org, "admin")
	seedHeld(t, pool, org, user, kept)
	seedHeld(t, pool, org, user, dropped)

	require.NoError(t, svc.UpdateUserRoles(ctx, user, []string{kept}, "admin"))

	require.True(t, revoked(t, revoke, user),
		"a replacement dropped a role and the token naming it was not cut")
}

// Replacing a set with itself loses nothing.
func TestReplacingASetWithItselfDoesNotRevoke(t *testing.T) {
	svc, pool, _, revoke, ctx, org := roleLossFixture(t)
	user := uuid.NewString()
	role := seedRole(t, pool, org, "reader")
	seedHeld(t, pool, org, user, role)

	require.NoError(t, svc.UpdateUserRoles(ctx, user, []string{role}, "admin"))

	require.False(t, revoked(t, revoke, user), "a no-op replacement cut a live session")
}

// lostRoles is the whole of the grant/revoke distinction, so it is pinned
// directly as well as through the paths above.
func TestLostRolesIsTheDifferenceNotTheUnion(t *testing.T) {
	require.Nil(t, lostRoles([]string{"a"}, []string{"a", "b"}), "a pure addition loses nothing")
	require.Equal(t, []string{"b"}, lostRoles([]string{"a", "b"}, []string{"a"}))
	require.Equal(t, []string{"a"}, lostRoles([]string{"a"}, nil), "an empty new set loses everything")
	require.Nil(t, lostRoles(nil, []string{"a"}))
	require.Nil(t, lostRoles([]string{"a"}, []string{"a"}))
}
