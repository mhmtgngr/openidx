package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestNotifyPamGrant proves a group PAM grant produces one in-app notification
// per group member, and that recipient resolution treats user/group/role right.
func TestNotifyPamGrant(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	schema := []string{
		`CREATE TABLE pam_entries (id UUID PRIMARY KEY, org_id UUID, name VARCHAR(255))`,
		`CREATE TABLE group_memberships (group_id UUID, user_id UUID, org_id UUID)`,
		`CREATE TABLE notifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL, org_id UUID, channel VARCHAR(50), type VARCHAR(100),
			title VARCHAR(255), body TEXT, link VARCHAR(500), read BOOLEAN DEFAULT false,
			metadata JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE notification_preferences (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, channel VARCHAR(50),
			event_type VARCHAR(100), enabled BOOLEAN, created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW())`,
	}
	for _, q := range schema {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const (
		org   = "00000000-0000-0000-0000-000000000010"
		entry = "eeeeeeee-0000-0000-0000-000000000001"
		grp   = "22222222-2222-2222-2222-222222222222"
		u1    = "11111111-1111-1111-1111-111111111111"
		u2    = "11111111-1111-1111-1111-111111111112"
	)
	exec := func(q string, args ...any) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("exec: %v", err)
		}
	}
	exec(`INSERT INTO pam_entries (id, org_id, name) VALUES ($1,$2,'prod-db')`, entry, org)
	exec(`INSERT INTO group_memberships (group_id, user_id, org_id) VALUES ($1,$2,$3),($1,$4,$3)`, grp, u1, org, u2)

	s := &Service{db: db, logger: zap.NewNop()}

	// Recipient resolution.
	if r, _ := s.grantRecipientUserIDs(ctx, org, "user", u1); len(r) != 1 || r[0] != u1 {
		t.Errorf("user recipients: want [%s], got %v", u1, r)
	}
	if r, _ := s.grantRecipientUserIDs(ctx, org, "role", "admin"); len(r) != 0 {
		t.Errorf("role recipients: want none, got %v", r)
	}
	if r, _ := s.grantRecipientUserIDs(ctx, org, "group", grp); len(r) != 2 {
		t.Errorf("group recipients: want 2 members, got %v", r)
	}

	// A group grant notifies every member.
	s.notifyPamGrant(ctx, org, entry, "group", grp)

	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM notifications WHERE type = 'access_granted' AND org_id = $1`, org,
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 access_granted notifications (one per member), got %d", n)
	}
}
