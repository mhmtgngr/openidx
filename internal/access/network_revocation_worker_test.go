package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestDrainNetworkRevocations verifies the worker claims pending intents,
// processes them (severUserZitiCircuits is a safe no-op without an overlay), and
// marks them done.
func TestDrainNetworkRevocations(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, `
        CREATE TABLE network_revocation_queue (id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, reason VARCHAR(64) NOT NULL, state VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
        CREATE TABLE ziti_identities (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, ziti_id VARCHAR(255), org_id UUID);
        CREATE TABLE enrolled_agents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID, ziti_identity_id VARCHAR(255));`)

	// Two pending intents for two users.
	db.Pool.Exec(ctx, `INSERT INTO network_revocation_queue (user_id, reason) VALUES
        ('11111111-1111-1111-1111-111111111111','access_review'),
        ('22222222-2222-2222-2222-222222222222','jit_expiry')`)

	s := &Service{db: db, logger: zap.NewNop()}
	s.drainNetworkRevocations(ctx)

	var pending, done int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_revocation_queue WHERE state='pending'`).Scan(&pending)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_revocation_queue WHERE state='done'`).Scan(&done)
	if pending != 0 {
		t.Errorf("expected 0 pending after drain, got %d", pending)
	}
	if done != 2 {
		t.Errorf("expected 2 done after drain, got %d", done)
	}
}
