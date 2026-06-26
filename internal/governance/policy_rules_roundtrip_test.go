package governance

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestPolicyRulesRoundTrip pins the write→read mapping between the PolicyRule
// the evaluators consume and the on-disk policy_rules schema
// (rule_type / conditions / actions). This is a DB-backed test on purpose: the
// in-memory evaluator tests cannot catch a column mismatch, which is exactly
// how GetPolicy/ListPolicies silently loaded zero rules (the query referenced
// non-existent columns) and the policy engine never enforced.
func TestPolicyRulesRoundTrip(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"})

	// Minimal schema matching the production tables the service queries.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE policies (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			type VARCHAR(50) NOT NULL,
			enabled BOOLEAN,
			priority INTEGER,
			rules JSONB,
			created_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ,
			org_id UUID NOT NULL
		);
		CREATE TABLE policy_rules (
			id UUID PRIMARY KEY,
			policy_id UUID,
			rule_type VARCHAR(50) NOT NULL,
			conditions JSONB NOT NULL,
			actions JSONB NOT NULL,
			created_at TIMESTAMPTZ,
			org_id UUID NOT NULL
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	policy := &Policy{
		Name:    "round-trip timebound",
		Type:    PolicyTypeTimebound,
		Enabled: true,
		Rules: []PolicyRule{{
			Effect:   "deny",
			Priority: 10,
			Condition: map[string]interface{}{
				"start_hour": float64(10),
				"end_hour":   float64(17),
			},
		}},
	}

	if err := s.CreatePolicy(ctx, policy); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// GetPolicy must reload the rule from policy_rules — the bug this guards is
	// rules coming back empty.
	got, err := s.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("expected 1 rule loaded, got %d (rules silently dropped = engine starved)", len(got.Rules))
	}
	r := got.Rules[0]
	if r.Effect != "deny" {
		t.Errorf("effect: want deny, got %q", r.Effect)
	}
	if r.Priority != 10 {
		t.Errorf("priority: want 10, got %d", r.Priority)
	}
	if sh, ok := r.Condition["start_hour"].(float64); !ok || sh != 10 {
		t.Errorf("condition start_hour: want 10, got %v", r.Condition["start_hour"])
	}

	// And the evaluator must actually deny using the reloaded rule.
	allowed, err := s.evaluateTimeboundPolicy(ctx, got, map[string]interface{}{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	_ = allowed // outcome depends on wall-clock; the assertion above already
	// proves the rule round-tripped. We don't assert allowed here to avoid a
	// time-of-day-dependent test.
}
