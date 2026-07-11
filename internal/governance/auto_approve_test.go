package governance

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestAutoApproveConditions guards the V-007 completion: approval policies'
// typed auto_approve_conditions are now evaluated at request creation,
// fail-closed, and a passing set approves + fulfills through the same path as
// the final manual decision.
func TestAutoApproveConditions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	ddl := []string{
		`CREATE TABLE access_requests (
			id UUID PRIMARY KEY, requester_id UUID, resource_type VARCHAR(50),
			resource_id VARCHAR(255), resource_name VARCHAR(255), status VARCHAR(50),
			expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID NOT NULL)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(255), org_id UUID NOT NULL)`,
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID, PRIMARY KEY (user_id, role_id))`,
		`CREATE TABLE groups (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(255), org_id UUID NOT NULL)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID, PRIMARY KEY (user_id, group_id))`,
		`CREATE TABLE mfa_totp (user_id UUID, enabled BOOLEAN, org_id UUID)`,
		`CREATE TABLE mfa_webauthn (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID)`,
		`CREATE TABLE audit_events (id UUID PRIMARY KEY, event_type VARCHAR(50), category VARCHAR(50),
			action VARCHAR(100), outcome VARCHAR(20), actor_id VARCHAR(255), actor_ip VARCHAR(45),
			target_id VARCHAR(255), target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ, org_id UUID)`,
	}
	for _, q := range ddl {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema (%s): %v", q, err)
		}
	}

	const (
		orgA      = "00000000-0000-0000-0000-00000000000a"
		requester = "11111111-0000-0000-0000-00000000000a"
		reqID     = "22222222-0000-0000-0000-000000000001"
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO roles (name, org_id) VALUES ('employee', $1)`, orgA)
	exec(`INSERT INTO user_roles SELECT $1, id, $2 FROM roles WHERE name = 'employee'`, requester, orgA)
	exec(`INSERT INTO groups (name, org_id) VALUES ('target-group', $1)`, orgA)
	exec(`INSERT INTO mfa_totp (user_id, enabled, org_id) VALUES ($1, true, $2)`, requester, orgA)

	var targetGroup string
	if err := db.Pool.QueryRow(ctx, `SELECT id::text FROM groups WHERE name = 'target-group'`).Scan(&targetGroup); err != nil {
		t.Fatalf("group id: %v", err)
	}
	exec(`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, status, org_id)
	      VALUES ($1, $2, 'group', $3, 'target-group', 'pending', $4)`, reqID, requester, targetGroup, orgA)

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	boolTrue := true

	// --- Evaluation-only semantics (no side effects) ---
	eval := func(c *AutoApproveConditions) bool {
		return s.autoApproveConditionsMet(ctxA, orgA, requester, c)
	}
	if eval(&AutoApproveConditions{}) {
		t.Fatal("empty conditions must NOT auto-approve (manual approval is the default)")
	}
	if !eval(&AutoApproveConditions{AllowedRoles: []string{"employee"}}) {
		t.Fatal("requester holds an allowed role; conditions should hold")
	}
	if eval(&AutoApproveConditions{AllowedRoles: []string{"admin"}}) {
		t.Fatal("requester lacks the allowed role; must not hold")
	}
	if !eval(&AutoApproveConditions{AllowedRoles: []string{"employee"}, RequireMFA: &boolTrue}) {
		t.Fatal("role + MFA both hold; conditions should hold")
	}
	maxRisk := 50
	if eval(&AutoApproveConditions{AllowedRoles: []string{"employee"}, MaxRiskScore: &maxRisk}) {
		t.Fatal("max_risk_score is not auto-evaluated; must fail closed")
	}
	maxCount := 5
	if eval(&AutoApproveConditions{AllowedRoles: []string{"employee"}, MaxRequestCount: &maxCount}) {
		t.Fatal("max_request_count is not auto-evaluated; must fail closed")
	}

	// A different user without the role must not pass.
	if s.autoApproveConditionsMet(ctxA, orgA, "11111111-0000-0000-0000-00000000000b",
		&AutoApproveConditions{AllowedRoles: []string{"employee"}}) {
		t.Fatal("stranger must not satisfy role condition")
	}

	// --- End-to-end: approve + fulfill through the manual-decision path ---
	if ok := s.tryAutoApprove(ctxA, reqID, &AutoApproveConditions{AllowedRoles: []string{"employee"}}); !ok {
		t.Fatal("tryAutoApprove should succeed for a passing condition set")
	}
	var status string
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM access_requests WHERE id = $1`, reqID).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("request status: want approved, got %q (err %v)", status, err)
	}
	var memberships int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM group_memberships WHERE user_id = $1 AND group_id = $2 AND org_id = $3`,
		requester, targetGroup, orgA).Scan(&memberships)
	if memberships != 1 {
		t.Fatalf("fulfillment: want the group membership granted, got %d rows", memberships)
	}
	var audits int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'access_request.auto_approved' AND target_id = $1`,
		reqID).Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit: want 1 auto_approved event, got %d", audits)
	}
}
