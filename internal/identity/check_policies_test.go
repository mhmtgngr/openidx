package identity

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestCheckPolicies_SeparationOfDuty is a DB-backed regression test for the
// separation-of-duty gate in CheckPolicies. It pins the write→read column
// mapping against the real policy_rules schema (rule_type / conditions /
// actions). The bug it guards: the query used to select pr.condition/pr.effect/
// pr.priority — columns that do not exist — so every call errored and fell
// through the "fail open" path, meaning SoD was never enforced and two
// conflicting roles could always be assigned together. An in-memory test cannot
// catch a column mismatch; only a query against the real schema can.
func TestCheckPolicies_SeparationOfDuty(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	// Minimal schema matching the production columns CheckPolicies + GetUserRoles
	// touch. policy_rules deliberately has NO condition/effect/priority columns —
	// that is the on-disk reality the fixed query must read from (conditions,
	// actions, rule_type).
	schema := []string{
		`CREATE TABLE policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			type VARCHAR(50) NOT NULL,
			enabled BOOLEAN DEFAULT true,
			priority INTEGER DEFAULT 0,
			org_id UUID NOT NULL)`,
		`CREATE TABLE policy_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id UUID NOT NULL,
			rule_type VARCHAR(50) NOT NULL,
			conditions JSONB NOT NULL,
			actions JSONB NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL)`,
		`CREATE TABLE roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			description TEXT DEFAULT '',
			is_composite BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL)`,
		`CREATE TABLE user_roles (
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			org_id UUID NOT NULL,
			assigned_by UUID,
			assigned_at TIMESTAMPTZ DEFAULT now(),
			expires_at TIMESTAMPTZ)`,
	}
	for _, s := range schema {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	adminRole := "aaaaaaaa-0000-0000-0000-000000000001"
	auditorRole := "aaaaaaaa-0000-0000-0000-000000000002"
	viewerRole := "aaaaaaaa-0000-0000-0000-000000000003"
	user := "bbbbbbbb-0000-0000-0000-000000000001"

	seed := func() {
		if _, err := db.Pool.Exec(ctx, `TRUNCATE policies, policy_rules, roles, user_roles`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		for id, name := range map[string]string{
			adminRole:   "admin",
			auditorRole: "auditor",
			viewerRole:  "viewer",
		} {
			if _, err := db.Pool.Exec(ctx,
				`INSERT INTO roles (id, name, org_id) VALUES ($1,$2,$3)`, id, name, orgID); err != nil {
				t.Fatalf("seed role: %v", err)
			}
		}
		// A separation-of-duty policy: admin and auditor may not be held together.
		policyID := "cccccccc-0000-0000-0000-000000000001"
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO policies (id, name, type, enabled, priority, org_id)
			 VALUES ($1, 'SoD: admin vs auditor', 'separation_of_duty', true, 100, $2)`,
			policyID, orgID); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
		// Stored exactly as governance.CreatePolicy writes it: the condition map in
		// `conditions`, {effect, priority} in `actions`, effect mirrored in rule_type.
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO policy_rules (policy_id, rule_type, conditions, actions, org_id)
			 VALUES ($1, 'deny', $2, $3, $4)`,
			policyID,
			`{"conflicting_roles": ["admin", "auditor"]}`,
			`{"effect": "deny", "priority": 10}`,
			orgID); err != nil {
			t.Fatalf("seed policy rule: %v", err)
		}
		// The user already holds admin.
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`,
			user, adminRole, orgID); err != nil {
			t.Fatalf("seed user_role: %v", err)
		}
	}

	svc := &Service{db: db, logger: zap.NewNop()}

	t.Run("conflicting assignment is blocked", func(t *testing.T) {
		seed()
		// Assigning auditor to a user who already has admin violates the SoD policy.
		err := svc.CheckPolicies(ctx, user, "update_roles", []string{auditorRole}, "1.2.3.4")
		if err == nil {
			t.Fatal("expected a policy violation, got nil (SoD not enforced — the fail-open bug)")
		}
		var pv *PolicyViolationError
		if !errors.As(err, &pv) {
			t.Fatalf("expected *PolicyViolationError, got %T: %v", err, err)
		}
		if len(pv.Violations) == 0 {
			t.Fatal("PolicyViolationError carried no violations")
		}
		if pv.Violations[0].Effect != "deny" {
			t.Errorf("violation effect: want deny, got %q", pv.Violations[0].Effect)
		}
	})

	t.Run("non-conflicting assignment is allowed", func(t *testing.T) {
		seed()
		// viewer does not conflict with admin, so the policy must not block it.
		if err := svc.CheckPolicies(ctx, user, "update_roles", []string{viewerRole}, "1.2.3.4"); err != nil {
			t.Fatalf("non-conflicting assignment should pass, got %v", err)
		}
	})
}

// TestCheckPolicies_FailsClosedOnDBError verifies the preventive control fails
// closed: when the policy query cannot run (here, the policies table is absent),
// CheckPolicies must deny the operation rather than silently allow it — the
// opposite of the original fail-open behavior.
func TestCheckPolicies_FailsClosedOnDBError(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	// Deliberately do NOT create the policies/policy_rules tables, so the query
	// inside CheckPolicies errors on a missing relation.
	svc := &Service{db: db, logger: zap.NewNop()}

	err := svc.CheckPolicies(ctx, "bbbbbbbb-0000-0000-0000-000000000001", "update_roles",
		[]string{"aaaaaaaa-0000-0000-0000-000000000002"}, "1.2.3.4")
	if err == nil {
		t.Fatal("expected a fail-closed denial when policies cannot be evaluated, got nil")
	}
	var pv *PolicyViolationError
	if !errors.As(err, &pv) {
		t.Fatalf("expected *PolicyViolationError, got %T: %v", err, err)
	}
}
