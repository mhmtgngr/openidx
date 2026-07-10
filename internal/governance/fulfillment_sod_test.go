package governance

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestCheckSoDForRoleGrant guards the access-request fulfillment back door: a
// role that conflicts with the requester's existing roles must be refused at
// fulfillment, the same way the direct role-update path refuses it. Otherwise a
// user could obtain a separation-of-duty-conflicting role simply by requesting
// it. DB-backed because the gate evaluates real policy rows.
func TestCheckSoDForRoleGrant(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE policies (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			type VARCHAR(50) NOT NULL,
			enabled BOOLEAN DEFAULT true,
			priority INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT now(),
			updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
		CREATE TABLE policy_rules (
			id UUID PRIMARY KEY,
			policy_id UUID NOT NULL,
			rule_type VARCHAR(50) NOT NULL,
			conditions JSONB NOT NULL,
			actions JSONB NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
		CREATE TABLE roles (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			org_id UUID NOT NULL);
		CREATE TABLE user_roles (
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			org_id UUID NOT NULL,
			expires_at TIMESTAMPTZ);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		adminRole   = "aaaaaaaa-0000-0000-0000-000000000001"
		auditorRole = "aaaaaaaa-0000-0000-0000-000000000002"
		viewerRole  = "aaaaaaaa-0000-0000-0000-000000000003"
		user        = "bbbbbbbb-0000-0000-0000-000000000001"
		policyID    = "cccccccc-0000-0000-0000-000000000001"
	)

	exec := func(q string, args ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	for id, name := range map[string]string{adminRole: "admin", auditorRole: "auditor", viewerRole: "viewer"} {
		exec(`INSERT INTO roles (id, name, org_id) VALUES ($1,$2,$3)`, id, name, orgID)
	}
	// description must be non-NULL: GetPolicy scans it into a plain string
	// (production writes "" via CreatePolicy, never NULL).
	exec(`INSERT INTO policies (id, name, description, type, enabled, priority, org_id)
	      VALUES ($1, 'SoD: admin vs auditor', '', 'separation_of_duty', true, 100, $2)`, policyID, orgID)
	exec(`INSERT INTO policy_rules (id, policy_id, rule_type, conditions, actions, org_id)
	      VALUES (gen_random_uuid(), $1, 'deny', $2, $3, $4)`,
		policyID, `{"conflicting_roles": ["admin", "auditor"]}`, `{"effect": "deny", "priority": 10}`, orgID)
	// The requester already holds admin.
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, user, adminRole, orgID)

	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	t.Run("conflicting role grant is blocked", func(t *testing.T) {
		err := s.checkSoDForRoleGrant(ctx, user, auditorRole)
		if err == nil {
			t.Fatal("expected a SoD violation granting auditor to an admin, got nil (fulfillment back door)")
		}
		var sod *SoDViolationError
		if !errors.As(err, &sod) {
			t.Fatalf("expected *SoDViolationError, got %T: %v", err, err)
		}
	})

	t.Run("non-conflicting role grant is allowed", func(t *testing.T) {
		if err := s.checkSoDForRoleGrant(ctx, user, viewerRole); err != nil {
			t.Fatalf("granting viewer (no conflict) should pass, got %v", err)
		}
	})
}
