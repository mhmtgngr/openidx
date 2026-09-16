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

// A GROUP IS A CLAIM, SO LOSING ONE IS A REVOCATION.
//
// internal/oauth builds "groups" onto the token from group_memberships at
// issuance, exactly as it builds "roles" from user_roles. The role half was
// closed; the group half was not, and nothing noticed because removing a
// membership does not touch the user row, which is the only shape the sever
// census recognised.
//
// Deleting a GROUP is the sharper case: it is a mass removal that names nobody.
// Like DeleteRole before it, the repository cut by predicate and reported
// nothing, so the caller had no identities to revoke — the fourth time this
// programme has needed RETURNING for that reason.

func groupSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS groups (id uuid PRIMARY KEY, name text, org_id uuid);
		CREATE TABLE IF NOT EXISTS group_memberships (user_id uuid, group_id uuid, org_id uuid);`)
	require.NoError(t, err)
}

func groupSvc(t *testing.T, pool *pgxpool.Pool, general, revoke *goredis.Client) *Service {
	t.Helper()
	s := expirySvc(t, pool, general, revoke)
	s.groups = &PostgresGroupRepository{db: s.db}
	return s
}

func marker(t *testing.T, r *goredis.Client, userID string) bool {
	t.Helper()
	n, err := r.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	return n > 0
}

func seedMembership(t *testing.T, pool *pgxpool.Pool, userID, groupID, org string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid,$2::uuid,$3::uuid)`,
		userID, groupID, org)
	require.NoError(t, err)
}

func TestRemovingAGroupMemberCutsTheTokenStillAssertingIt(t *testing.T) {
	pool := openExpiryPool(t)
	groupSchema(t, pool)
	general, revoke := openExpiryRedis(t)
	org, group, user := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	seedMembership(t, pool, user, group, org)

	require.NoError(t, groupSvc(t, pool, general, revoke).RemoveGroupMember(ctx, group, user))

	require.True(t, marker(t, revoke, user), "the token still asserts the group; it must be cut")
	require.False(t, marker(t, general, user), "the marker must not go to the general Redis")
}

// A removal that removed nothing is not a revocation, and logging the user out
// would be an outage the administrator did not ask for.
func TestRemovingANonMemberCutsNothing(t *testing.T) {
	pool := openExpiryPool(t)
	groupSchema(t, pool)
	general, revoke := openExpiryRedis(t)
	org, group, user := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	err := groupSvc(t, pool, general, revoke).RemoveGroupMember(ctx, group, user)
	require.ErrorIs(t, err, ErrNotGroupMember)
	require.False(t, marker(t, revoke, user), "nothing was taken away, so nothing should be cut")
}

// Deleting a group revokes it from everyone who held it, and the path cut by
// predicate: it had no identity to revoke until it said which rows it took.
func TestDeletingAGroupCutsEveryMemberItSilentlyRemoved(t *testing.T) {
	pool := openExpiryPool(t)
	groupSchema(t, pool)
	general, revoke := openExpiryRedis(t)
	org, group := uuid.NewString(), uuid.NewString()
	a, b := uuid.NewString(), uuid.NewString()
	outsider := uuid.NewString()
	otherGroup := uuid.NewString()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	_, err := pool.Exec(ctx, `INSERT INTO groups (id, name, org_id) VALUES ($1::uuid,'g',$2::uuid)`, group, org)
	require.NoError(t, err)
	seedMembership(t, pool, a, group, org)
	seedMembership(t, pool, b, group, org)
	seedMembership(t, pool, outsider, otherGroup, org)

	require.NoError(t, groupSvc(t, pool, general, revoke).DeleteGroup(ctx, group))

	require.True(t, marker(t, revoke, a), "every member who lost the group must be cut")
	require.True(t, marker(t, revoke, b), "every member who lost the group must be cut")
	require.False(t, marker(t, revoke, outsider), "a member of a different group must not be cut")
	require.False(t, marker(t, general, a), "the marker must not go to the general Redis")
}

// The rows are gone either way, so the install without Redis must still delete:
// refusing would leave the membership in place, which is worse than removing it
// and not cutting.
func TestGroupRemovalStillWorksWithNoRedis(t *testing.T) {
	pool := openExpiryPool(t)
	groupSchema(t, pool)
	org, group, user := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	seedMembership(t, pool, user, group, org)

	s := expirySvc(t, pool, nil, nil)
	s.redis = nil
	s.groups = &PostgresGroupRepository{db: s.db}
	require.NoError(t, s.RemoveGroupMember(ctx, group, user))

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE user_id=$1::uuid`, user).Scan(&n))
	require.Equal(t, 0, n, "the membership must still be removed without Redis")
}
