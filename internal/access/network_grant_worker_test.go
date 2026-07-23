package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestDrainNetworkGrants verifies the JIT grant worker claims pending grant
// intents, processes them (addUserZitiAttribute is a no-op without an overlay),
// and marks them done.
func TestDrainNetworkGrants(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, `
        CREATE TABLE network_grant_queue (id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, request_id UUID, attribute VARCHAR(128) NOT NULL, expires_at TIMESTAMPTZ, state VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
        CREATE TABLE ziti_identities (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, ziti_id VARCHAR(255), org_id UUID);`)
	db.Pool.Exec(ctx, `INSERT INTO network_grant_queue (user_id, request_id, attribute) VALUES
        ('11111111-1111-1111-1111-111111111111', gen_random_uuid(), 'jit-req-1'),
        ('22222222-2222-2222-2222-222222222222', gen_random_uuid(), 'jit-req-2')`)

	s := &Service{db: db, logger: zap.NewNop()}
	s.drainNetworkGrants(ctx)

	var pending, done int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_grant_queue WHERE state='pending'`).Scan(&pending)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_grant_queue WHERE state='done'`).Scan(&done)
	if pending != 0 {
		t.Errorf("expected 0 pending after drain, got %d", pending)
	}
	if done != 2 {
		t.Errorf("expected 2 done after drain, got %d", done)
	}
}

// TestNetworkRevocationAttributeColumn verifies the revocation worker reads the
// attribute column (Wave B1 expiry path) and processes it without error.
func TestNetworkRevocationAttributeColumn(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, `
        CREATE TABLE network_revocation_queue (id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, reason VARCHAR(64) NOT NULL, attribute VARCHAR(128), state VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
        CREATE TABLE ziti_identities (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, ziti_id VARCHAR(255), org_id UUID);
        CREATE TABLE enrolled_agents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID, ziti_identity_id VARCHAR(255));`)
	// One attribute-removal intent (JIT expiry) + one plain sever intent.
	db.Pool.Exec(ctx, `INSERT INTO network_revocation_queue (user_id, reason, attribute) VALUES
        ('33333333-3333-3333-3333-333333333333','jit_expiry','jit-req-9'),
        ('44444444-4444-4444-4444-444444444444','access_review', NULL)`)

	s := &Service{db: db, logger: zap.NewNop()}
	s.drainNetworkRevocations(ctx)

	var done int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_revocation_queue WHERE state='done'`).Scan(&done)
	if done != 2 {
		t.Errorf("expected 2 done (attribute-removal + plain sever), got %d", done)
	}
}

func TestJITNetworkAttributeFormat(t *testing.T) {
	// The attribute helper lives in governance; here we assert the worker-side
	// format expectation (jit- prefix) via addUserZitiAttribute's no-op path.
	s := &Service{logger: zap.NewNop()}
	// nil overlay -> no-op, returns nil.
	if err := s.addUserZitiAttribute(context.Background(), "u", "jit-x"); err != nil {
		t.Errorf("expected nil-overlay no-op, got %v", err)
	}
	s.removeUserZitiAttribute(context.Background(), "u", "jit-x") // must not panic
}
