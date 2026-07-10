package governance

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestCreateApprovalRows_RoleStep guards the role-based approval tier. An
// approval policy step of type "role" must create a pending approver row for
// every holder of that role. The old query read a nonexistent users.roles
// column, errored, was swallowed, and created zero rows — so a role approval
// requirement silently approved nothing, and a mixed [specific_user, role]
// policy auto-fulfilled the moment the specific user approved (pendingCount
// hit 0). DB-backed because createApprovalRows runs real queries.
func TestCreateApprovalRows_RoleStep(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE approval_policies (
			id UUID PRIMARY KEY,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			approval_steps JSONB NOT NULL,
			enabled BOOLEAN DEFAULT true,
			org_id UUID NOT NULL);
		CREATE TABLE user_roles (
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			org_id UUID NOT NULL);
		CREATE TABLE access_request_approvals (
			id UUID PRIMARY KEY,
			request_id UUID NOT NULL,
			approver_id UUID NOT NULL,
			step_order INTEGER NOT NULL,
			decision VARCHAR(20) NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		roleID    = "aaaaaaaa-0000-0000-0000-000000000001"
		approver1 = "bbbbbbbb-0000-0000-0000-000000000001"
		approver2 = "bbbbbbbb-0000-0000-0000-000000000002"
		policyID  = "cccccccc-0000-0000-0000-000000000001"
		requestID = "eeeeeeee-0000-0000-0000-000000000001"
	)

	exec := func(q string, args ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	// Two users hold the approver role; a third grant of the same role to
	// approver1 must NOT double-count (DISTINCT).
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, approver1, roleID, orgID)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, approver2, roleID, orgID)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, approver1, roleID, orgID)
	// A policy that requires approval from that role (resource_id NULL => generic).
	steps := fmt.Sprintf(`[{"order":1,"type":"role","role_id":"%s"}]`, roleID)
	exec(`INSERT INTO approval_policies (id, resource_type, resource_id, approval_steps, enabled, org_id)
	      VALUES ($1, 'role', NULL, $2, true, $3)`, policyID, steps, orgID)

	s := &Service{db: db, logger: zaptest.NewLogger(t)}
	s.createApprovalRows(ctx, requestID, "role", "ffffffff-0000-0000-0000-000000000001")

	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id=$1 AND decision='pending' AND org_id=$2`,
		requestID, orgID).Scan(&n); err != nil {
		t.Fatalf("count approvals: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 distinct role holders seeded as pending approvers, got %d (role approval tier silently voided)", n)
	}

	// Each approver row must reference a real role holder, not the admin default.
	rows, err := db.Pool.Query(ctx,
		`SELECT approver_id FROM access_request_approvals WHERE request_id=$1 AND org_id=$2`, requestID, orgID)
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = true
	}
	if !got[approver1] || !got[approver2] {
		t.Fatalf("expected approvers %s and %s, got %v", approver1, approver2, got)
	}
}
