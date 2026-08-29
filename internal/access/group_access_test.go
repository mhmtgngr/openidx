package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestPamEntryAllowed_GroupGrant proves group membership grants PAM access:
// a ('group', <gid>) grant on an entry allows every member, while a user in
// no granted group (and with no user/role grant) is denied.
func TestPamEntryAllowed_GroupGrant(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE pam_entry_grants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID NOT NULL,
			entry_id UUID NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			principal_id VARCHAR(255) NOT NULL,
			actions TEXT[] NOT NULL,
			expires_at TIMESTAMPTZ
		)`,
		`CREATE TABLE group_memberships (
			group_id UUID NOT NULL,
			user_id UUID NOT NULL,
			org_id UUID NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const (
		org      = "00000000-0000-0000-0000-000000000010"
		entry    = "eeeeeeee-0000-0000-0000-000000000001"
		grp      = "22222222-2222-2222-2222-222222222222"
		member   = "11111111-1111-1111-1111-111111111111"
		outsider = "33333333-3333-3333-3333-333333333333"
	)
	// Grant is to the GROUP, not to either user directly.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		 VALUES ($1,$2,'group',$3,ARRAY['connect'])`, org, entry, grp); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	// member belongs to the granted group; outsider does not.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO group_memberships (group_id, user_id, org_id) VALUES ($1,$2,$3)`, grp, member, org); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	allowed, err := s.pamEntryAllowed(ctx, org, entry, member, nil, "connect")
	if err != nil {
		t.Fatalf("pamEntryAllowed(member): %v", err)
	}
	if !allowed {
		t.Error("group member should be allowed via ('group', gid) grant")
	}

	denied, err := s.pamEntryAllowed(ctx, org, entry, outsider, nil, "connect")
	if err != nil {
		t.Fatalf("pamEntryAllowed(outsider): %v", err)
	}
	if denied {
		t.Error("non-member with no user/role/group grant should be denied")
	}
}
