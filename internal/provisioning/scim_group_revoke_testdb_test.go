package provisioning

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

// AN IdP PUSHING A GROUP UPDATE IS THE COMMONEST WAY A MEMBERSHIP IS TAKEN AWAY
// IN THIS PRODUCT, AND "groups" IS A CLAIM ON THE ACCESS TOKEN.
//
// UpdateSCIMGroup clears every membership and re-inserts the ones the IdP still
// sends, so most of what it removes it puts straight back: cutting on the delete
// would log out every member of every SCIM-managed group on every push, for
// nothing. Only the DIFFERENCE is a revocation.
//
// DeleteSCIMGroup is the shape that hid. group_memberships.group_id carries
// ON DELETE CASCADE, so `DELETE FROM groups` removes every membership without
// the statement ever naming group_memberships — invisible to a census that
// reads SQL, and impossible to recover from afterwards, which is why the
// members are read before the delete.
//
// Measured against a real PostgreSQL and a real Redis, with the general and
// revocation roles on separate databases so a marker written to the wrong role
// is visible, and read back through the key the enforcement point reads.

func scimRedis(t *testing.T) (general, revoke *goredis.Client) {
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

const (
	scimOrg   = "00000000-0000-0000-0000-0000000000f1"
	scimGroup = "00000000-0000-0000-0000-0000000000f2"
	scimKeep  = "00000000-0000-0000-0000-0000000000f3"
	scimGone  = "00000000-0000-0000-0000-0000000000f4"
)

// scimGroupFixture builds the real cascade: group_memberships references groups
// ON DELETE CASCADE, exactly as migration 001 declares it. Without that the
// delete test would be measuring a fixture, not the database's behaviour.
func scimGroupFixture(t *testing.T, db *database.PostgresDB, ctx context.Context) {
	t.Helper()
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE groups (
			id UUID PRIMARY KEY, name VARCHAR(255), description TEXT, external_id VARCHAR(255),
			org_id UUID NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
		CREATE TABLE group_memberships (
			user_id UUID NOT NULL,
			group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			joined_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL,
			PRIMARY KEY (user_id, group_id));
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), event_type VARCHAR(50), category VARCHAR(50),
			action VARCHAR(100), outcome VARCHAR(20), actor_id UUID, actor_ip VARCHAR(45), target_id UUID,
			target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);`)
	require.NoError(t, err)

	_, err = db.Pool.Exec(ctx,
		`INSERT INTO groups (id, name, org_id) VALUES ($1, 'engineering', $2)`, scimGroup, scimOrg)
	require.NoError(t, err)
	for _, u := range []string{scimKeep, scimGone} {
		_, err = db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, u, scimGroup, scimOrg)
		require.NoError(t, err)
	}
}

func scimSvc(t *testing.T, db *database.PostgresDB, general, revoke *goredis.Client) *Service {
	t.Helper()
	s := &Service{db: db, logger: zap.NewNop()}
	if general != nil {
		s.redis = &database.RedisClient{Client: general, Revocation: revoke}
	}
	return s
}

func scimCut(t *testing.T, r *goredis.Client, userID string) bool {
	t.Helper()
	n, err := r.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	return n > 0
}

func TestASCIMGroupUpdateCutsOnlyTheMembersItDropped(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)
	general, revoke := scimRedis(t)

	_, err := scimSvc(t, db, general, revoke).UpdateSCIMGroup(ctx, scimGroup, &SCIMGroup{
		DisplayName: "engineering",
		Members:     []SCIMMember{{Value: scimKeep}},
	})
	require.NoError(t, err)

	require.True(t, scimCut(t, revoke, scimGone), "the dropped member's token still asserts the group")
	require.False(t, scimCut(t, revoke, scimKeep),
		"a member the IdP still sends must not be logged out; that would be every member of every SCIM group on every push")
	require.False(t, scimCut(t, general, scimGone), "the marker must not go to the general Redis")
}

// The commonest push of all changes nothing.
func TestASCIMGroupUpdateThatChangesNothingCutsNobody(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)
	general, revoke := scimRedis(t)

	_, err := scimSvc(t, db, general, revoke).UpdateSCIMGroup(ctx, scimGroup, &SCIMGroup{
		DisplayName: "engineering",
		Members:     []SCIMMember{{Value: scimKeep}, {Value: scimGone}},
	})
	require.NoError(t, err)

	require.False(t, scimCut(t, revoke, scimKeep), "nobody lost anything")
	require.False(t, scimCut(t, revoke, scimGone), "nobody lost anything")
}

// A push with no Members at all touches no membership, so it must cut nobody —
// the nil check is what separates "the IdP sent an empty group" from "the IdP
// did not mention members".
func TestASCIMGroupUpdateWithoutMembersCutsNobody(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)
	general, revoke := scimRedis(t)

	_, err := scimSvc(t, db, general, revoke).UpdateSCIMGroup(ctx, scimGroup, &SCIMGroup{DisplayName: "renamed"})
	require.NoError(t, err)

	require.False(t, scimCut(t, revoke, scimKeep), "a rename is not a revocation")
	require.False(t, scimCut(t, revoke, scimGone), "a rename is not a revocation")

	var n int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE group_id=$1`, scimGroup).Scan(&n))
	require.Equal(t, 2, n, "a rename must not clear the membership")
}

// THE CASCADE. Every membership goes with the group, and the statement never
// names group_memberships.
func TestDeletingASCIMGroupCutsEveryMemberTheCascadeRemoved(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)
	general, revoke := scimRedis(t)

	require.NoError(t, scimSvc(t, db, general, revoke).DeleteSCIMGroup(ctx, scimGroup))

	// The database really did cascade -- otherwise this test would pass for the
	// wrong reason.
	var memberships int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE group_id=$1`, scimGroup).Scan(&memberships))
	require.Equal(t, 0, memberships, "the cascade must have removed the memberships")

	require.True(t, scimCut(t, revoke, scimKeep), "every member of a deleted group loses the claim")
	require.True(t, scimCut(t, revoke, scimGone), "every member of a deleted group loses the claim")
	require.False(t, scimCut(t, general, scimKeep), "the marker must not go to the general Redis")
}

// An install with no Redis must still apply the SCIM push: refusing would leave
// the membership live in the database as well as the token.
func TestTheSCIMGroupPathsWorkWithNoRedis(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)

	svc := scimSvc(t, db, nil, nil)
	_, err := svc.UpdateSCIMGroup(ctx, scimGroup, &SCIMGroup{
		DisplayName: "engineering",
		Members:     []SCIMMember{{Value: scimKeep}},
	})
	require.NoError(t, err)
	require.NoError(t, svc.DeleteSCIMGroup(ctx, scimGroup))

	var groups int
	require.NoError(t, db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE id=$1`, scimGroup).Scan(&groups))
	require.Equal(t, 0, groups, "the group must still be deleted without Redis")
}

// WHY THE REVOKE IS AFTER THE COMMIT AND NOT BESIDE THE DELETE.
//
// Redis cannot join a Postgres transaction. A marker written beside the DELETE
// survives a rollback that puts the membership back, so the user is still in
// the group and has been logged out of it, and the log reads as though a SCIM
// push had taken the access away.
//
// A failing DELETE does not separate the two placements — the function returns
// before either runs — so this forces the only shape that does: a DEFERRABLE
// constraint trigger that fires at COMMIT. The DELETE succeeds, the commit does
// not, and nothing must have been cut.
func TestASCIMGroupUpdateWhoseCommitFailsCutsNothing(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: scimOrg})
	scimGroupFixture(t, db, ctx)
	general, revoke := scimRedis(t)

	_, err := db.Pool.Exec(ctx, `
		CREATE FUNCTION scim_refuse_at_commit() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused at commit'; END; $$ LANGUAGE plpgsql;
		CREATE CONSTRAINT TRIGGER scim_refuse AFTER DELETE ON group_memberships
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION scim_refuse_at_commit();`)
	require.NoError(t, err)

	_, err = scimSvc(t, db, general, revoke).UpdateSCIMGroup(ctx, scimGroup, &SCIMGroup{
		DisplayName: "engineering",
		Members:     []SCIMMember{{Value: scimKeep}},
	})
	require.Error(t, err, "a commit that the database refuses must surface")

	var n int
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE group_id=$1`, scimGroup).Scan(&n))
	require.Equal(t, 2, n, "the rollback must have put both memberships back")

	require.False(t, scimCut(t, revoke, scimGone),
		"the commit failed and the membership is back, but the token was cut: a marker written inside a "+
			"transaction survives the rollback that undoes the removal")
}
