package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const notifyTestOrg = "00000000-0000-0000-0000-000000000010"

func TestNotifyUserOfTrustDecision(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: notifyTestOrg})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE notifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			org_id UUID,
			channel VARCHAR(32),
			type VARCHAR(64),
			title TEXT,
			body TEXT,
			link TEXT,
			read BOOLEAN DEFAULT false,
			metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	const userID = "00000000-0000-0000-0000-000000000001"

	s.notifyUserOfTrustDecision(ctx, userID, "approved", "looks good")

	var n int
	db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id=$1 AND type='device_trust'`, userID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 device_trust notification for the user, got %d", n)
	}
}

func TestNotifyAdminsOfTrustRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: notifyTestOrg})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE notifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL, org_id UUID, channel VARCHAR(32), type VARCHAR(64),
			title TEXT, body TEXT, link TEXT, read BOOLEAN DEFAULT false, metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(64), org_id UUID);
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const adminUser = "00000000-0000-0000-0000-0000000000aa"
	const adminRole = "60000000-0000-0000-0000-000000000001"
	// Two separate Exec calls: pgx's extended protocol rejects multiple
	// parameterized commands in a single query string.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1,'admin',$2)`, adminRole, notifyTestOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, adminUser, adminRole, notifyTestOrg); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	s.notifyAdminsOfTrustRequest(ctx, "00000000-0000-0000-0000-000000000001", "My Laptop")

	var n int
	db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id=$1 AND type='device_trust'`, adminUser).Scan(&n)
	if n != 1 {
		t.Fatalf("expected the admin to get 1 device_trust notification, got %d", n)
	}
}
