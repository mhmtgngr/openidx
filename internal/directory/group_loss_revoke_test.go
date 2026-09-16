package directory

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// A SYNC THAT DROPS SOMEBODY FROM A GROUP MUST CUT THE TOKEN THAT STILL SAYS
// THEY ARE IN IT — AND ONLY THEIRS.
//
// "groups" is a claim: internal/oauth builds it onto the access token from
// group_memberships at issuance. But both sync paths REPLACE the membership —
// delete every directory-managed row, insert the current ones — so most of what
// they remove they put straight back. Cutting on the delete would log out every
// member of every synced group on every sync, for nothing: a grant that has not
// reached the token permits nothing it should not. Only the DIFFERENCE is a
// revocation.
//
// The revoke is measured through the injected callback rather than Redis,
// because that injection is the boundary this package actually owns —
// revoker_wiring_test.go is what proves the binaries supply it, and
// internal/revocation's census records that name-based reachability cannot
// follow a function-valued field.

func TestAMembershipReplacementCutsOnlyTheMembersItDropped(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)

	rec := &recordingRevoker{}
	e := &SyncEngine{db: db, logger: zap.NewNop(), revoke: rec.fn}

	// memKeep stays, memGone does not.
	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if len(rec.calls()) != 1 || rec.calls()[0] != memGone {
		t.Fatalf("cut %v; want exactly the dropped member (%s). Cutting a member who is still in the group "+
			"is a logout on every sync that takes nothing away", rec.calls(), memGone)
	}
}

// The commonest sync of all changes nothing. It must end no sessions.
func TestAMembershipReplacementThatChangesNothingCutsNobody(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)

	rec := &recordingRevoker{}
	e := &SyncEngine{db: db, logger: zap.NewNop(), revoke: rec.fn}

	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep, memGone}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatalf("a sync that removed nobody cut %v; every member of every synced group would be logged "+
			"out on every sync", rec.calls())
	}
}

// Adding a member is not removing one.
func TestAMembershipReplacementThatOnlyAddsCutsNobody(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)

	const newcomer = "33333333-0000-0000-0000-000000000063"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, directory_id, org_id) VALUES ($1, $2, $3)`, newcomer, memDir, memOrg); err != nil {
		t.Fatalf("seed newcomer: %v", err)
	}

	rec := &recordingRevoker{}
	e := &SyncEngine{db: db, logger: zap.NewNop(), revoke: rec.fn}

	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep, memGone, newcomer}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatalf("granting a membership cut %v; a grant not yet in the token permits nothing it should not", rec.calls())
	}
}

// membershipsLost is the difference, not the union. Measured directly, because
// this is the asymmetry the whole design rests on.
func TestMembershipsLostIsTheDifference(t *testing.T) {
	for _, tc := range []struct {
		name          string
		removed, kept []string
		want          []string
	}{
		{"all restored", []string{"a", "b"}, []string{"a", "b"}, nil},
		{"one dropped", []string{"a", "b"}, []string{"a"}, []string{"b"}},
		{"all dropped", []string{"a", "b"}, nil, []string{"a", "b"}},
		{"duplicates cut once", []string{"a", "a"}, nil, []string{"a"}},
		{"blank ignored", []string{"", "a"}, nil, []string{"a"}},
		{"nothing removed", nil, []string{"a"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := membershipsLost(tc.removed, tc.kept)
			if len(got) != len(tc.want) {
				t.Fatalf("membershipsLost(%v, %v) = %v; want %v", tc.removed, tc.kept, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("membershipsLost(%v, %v) = %v; want %v", tc.removed, tc.kept, got, tc.want)
				}
			}
		})
	}
}

// THE CASCADE. Deleting the group takes every membership with it, and the
// statement never names group_memberships — so the members have to be read
// before the delete, and a census that only reads SQL cannot see this path at
// all.
func TestDeletingASyncedGroupCutsEveryMemberItHad(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)
	// The real schema cascades from groups; this fixture has no groups table,
	// so the delete is a no-op here and the assertion is about WHO gets cut,
	// which is what the cascade makes impossible to recover afterwards.
	if _, err := db.Pool.Exec(ctx, `CREATE TABLE groups (id UUID PRIMARY KEY, org_id UUID NOT NULL)`); err != nil {
		t.Fatalf("create groups: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO groups (id, org_id) VALUES ($1, $2)`, memGroup, memOrg); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	rec := &recordingRevoker{}
	e := &SyncEngine{db: db, logger: zap.NewNop(), revoke: rec.fn}

	if err := e.deleteSyncedGroup(ctx, memGroup, memOrg, "test"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	seen := map[string]bool{}
	for _, u := range rec.calls() {
		seen[u] = true
	}
	if !seen[memKeep] || !seen[memGone] {
		t.Fatalf("cut %v; a group that stopped existing must cut every member, and after the cascade there "+
			"is no way to find out who they were", rec.calls())
	}

	var groups int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE id = $1`, memGroup).Scan(&groups); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if groups != 0 {
		t.Fatal("the group must still be deleted")
	}
}

// An install that never wired a revoker must still sync. revokeTokens guards
// the nil callback; this proves the new paths go through that guard.
func TestTheSyncPathsRunWithNoRevokerWired(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)
	if _, err := db.Pool.Exec(ctx, `CREATE TABLE groups (id UUID PRIMARY KEY, org_id UUID NOT NULL)`); err != nil {
		t.Fatalf("create groups: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO groups (id, org_id) VALUES ($1, $2)`, memGroup, memOrg); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	e := &SyncEngine{db: db, logger: zap.NewNop()} // revoke stays nil

	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep}); err != nil {
		t.Fatalf("replace with no revoker: %v", err)
	}
	if err := e.deleteSyncedGroup(ctx, memGroup, memOrg, "test"); err != nil {
		t.Fatalf("delete with no revoker: %v", err)
	}
}
