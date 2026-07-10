package governance

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"
)

// TestRevokeExpiredJITAccess_LandsAuditRow guards the silent-audit-loss bug: the
// JIT expiry sweep wrote audit_events using a column `ip_address` that does not
// exist on the table (the real column is actor_ip), so every INSERT errored and
// the error was swallowed — expired access was revoked but left no audit trail.
// DB-backed because the whole defect is in whether the row actually lands.
func TestRevokeExpiredJITAccess_LandsAuditRow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	// Minimal schema matching the columns the sweep touches. audit_events mirrors
	// the canonical schema (actor_ip, org_id) that the audit service writes to.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			requester_id UUID NOT NULL,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID NOT NULL,
			resource_name VARCHAR(255),
			status VARCHAR(50) DEFAULT 'pending',
			expires_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL);
		CREATE TABLE user_roles (
			user_id UUID NOT NULL, role_id UUID NOT NULL, org_id UUID NOT NULL);
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			timestamp TIMESTAMPTZ DEFAULT NOW(),
			event_type VARCHAR(100) NOT NULL,
			category VARCHAR(50) NOT NULL,
			action VARCHAR(255) NOT NULL,
			outcome VARCHAR(50) NOT NULL,
			actor_id VARCHAR(255),
			actor_type VARCHAR(50),
			actor_ip VARCHAR(45),
			target_id VARCHAR(255),
			target_type VARCHAR(100),
			resource_id VARCHAR(255),
			details JSONB,
			session_id VARCHAR(255),
			request_id VARCHAR(255),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		orgID  = "00000000-0000-0000-0000-000000000010"
		user   = "bbbbbbbb-0000-0000-0000-000000000001"
		roleID = "aaaaaaaa-0000-0000-0000-000000000001"
	)
	// A fulfilled role request that expired an hour ago.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO access_requests (requester_id, resource_type, resource_id, resource_name, status, expires_at, org_id)
		VALUES ($1, 'role', $2, 'Admin', 'fulfilled', NOW() - INTERVAL '1 hour', $3)
	`, user, roleID, orgID); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, user, roleID, orgID); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	s := &Service{db: db, logger: zaptest.NewLogger(t)}
	s.revokeExpiredJITAccess(ctx)

	var roleCount int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_roles WHERE user_id=$1`, user).Scan(&roleCount); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if roleCount != 0 {
		t.Errorf("expired role should be revoked, still have %d", roleCount)
	}

	var status string
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM access_requests WHERE requester_id=$1`, user).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "expired" {
		t.Errorf("request status: want expired, got %q", status)
	}

	// The point of the test: an audit row actually lands.
	var auditCount int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='jit_access_expired' AND actor_id=$1 AND org_id=$2`,
		user, orgID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("jit expiry must land exactly one audit row, got %d (silent audit loss)", auditCount)
	}
}
