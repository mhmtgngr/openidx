package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestIsMFARequired covers the evaluator BEFORE it gates a login. It has never
// executed in production: the admin console has full CRUD over mfa_policies
// while nothing read the result, so every behaviour below is unverified until
// this test says otherwise.
func TestIsMFARequired(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		org  = "00000000-0000-0000-0000-0000000000d0"
		user = "11111111-0000-0000-0000-0000000000d1"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			description TEXT,
			enabled BOOLEAN DEFAULT true,
			priority INTEGER DEFAULT 0,
			conditions JSONB,
			required_methods JSONB,
			grace_period_hours INTEGER DEFAULT 24,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL)`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	// IsMFARequired logs on entry, so a bare &Service{db: db} nil-panics on the
	// logger. Build it the way the package's own tests do
	// (internal/identity/orgscope_test.go:21).
	svc := NewService(db, nil, nil, zap.NewNop())

	t.Run("no policies means not required", func(t *testing.T) {
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required || policy != nil {
			t.Errorf("got (%v, %+v), want (false, nil) — an empty table must not challenge anyone", required, policy)
		}
	})

	t.Run("a disabled policy is ignored", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('off', false, 10, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		required, _, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Error("a disabled policy must not require MFA")
		}
	})

	t.Run("an enabled matching policy requires MFA and is returned", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, grace_period_hours, org_id)
			VALUES ('always', true, 5, '{"factor_enrolled":true}', 12, $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if !required || policy == nil {
			t.Fatalf("got (%v, %+v), want required with the matching policy", required, policy)
		}
		if policy.GracePeriodHours != 12 {
			t.Errorf("grace_period_hours = %d, want 12 — the caller needs it to honour the grace window", policy.GracePeriodHours)
		}
	})

	t.Run("the highest priority policy wins", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('stronger', true, 99, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if policy == nil || policy.Name != "stronger" {
			t.Errorf("got %+v, want the priority-99 policy", policy)
		}
	})

	t.Run("another org's policy does not apply", func(t *testing.T) {
		otherCtx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-0000000000d9"})
		required, _, err := svc.IsMFARequired(otherCtx, user, "1.2.3.4")
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Error("policies must not leak across orgs")
		}
	})
}
