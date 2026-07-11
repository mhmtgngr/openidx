package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestUserGroupNames guards the phantom-table fix: the risk-evaluation group
// lookup (and its SAML/biometric siblings) used to JOIN a `user_groups` table
// that no migration creates, so the query always errored and the caller saw an
// empty group set — group-scoped risk policies silently never matched
// (fail-open). userGroupNames now reads the real group_memberships table,
// org-scoped via the groups join. DB-backed because it runs the real query.
func TestUserGroupNames(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255), org_id UUID);
		CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA = "00000000-0000-0000-0000-00000000000a"
		orgB = "00000000-0000-0000-0000-00000000000b"
		user = "11111111-0000-0000-0000-000000000001"
		gEng = "22222222-0000-0000-0000-000000000001" // Engineering, org A, user is a member
		gSal = "22222222-0000-0000-0000-000000000002" // Sales, org A, user NOT a member
		gOth = "22222222-0000-0000-0000-000000000003" // Other, org B, user is a member there
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO groups (id, name, org_id) VALUES ($1,'Engineering',$2),($3,'Sales',$2),($4,'Other',$5)`, gEng, orgA, gSal, gOth, orgB)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, user, gEng, orgA)
	// Membership in another org's group must NOT leak into the org-A view.
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3)`, user, gOth, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	got := s.userGroupNames(ctx, user, orgA)
	if len(got) != 1 || got[0] != "Engineering" {
		t.Fatalf("userGroupNames(user, orgA): want [Engineering] (member of Engineering only, org-scoped), got %v", got)
	}

	// A user with no memberships in the org resolves to an empty set (not an error).
	if got := s.userGroupNames(ctx, "33333333-0000-0000-0000-000000000000", orgA); len(got) != 0 {
		t.Fatalf("userGroupNames(stranger, orgA): want empty, got %v", got)
	}
}

// TestUserGroupNames_RequiresRealTable is a lightweight guard that the query
// targets group_memberships, not the phantom user_groups: pointed at a schema
// that has only user_groups, the lookup must fail to resolve (degrade to empty)
// rather than succeed — proving the fix reads the table that actually exists.
func TestUserGroupNames_RequiresRealTable(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	// Only the phantom table exists here; group_memberships does not.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE groups (id UUID PRIMARY KEY, name VARCHAR(255), org_id UUID);
		CREATE TABLE user_groups (user_id UUID, group_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	s := &Service{db: db, logger: zap.NewNop()}
	if got := s.userGroupNames(ctx, "11111111-0000-0000-0000-000000000001", "00000000-0000-0000-0000-00000000000a"); len(got) != 0 {
		t.Fatalf("with no group_memberships table the lookup must degrade to empty, got %v", got)
	}
}
