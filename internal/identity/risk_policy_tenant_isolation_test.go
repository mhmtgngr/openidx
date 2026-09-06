package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the login risk policies, migration v153.
//
// A risk_policies row is a rule the login path consults: when this condition
// holds, require MFA, require step-up, deny, or allow these factors. Until v153
// the table had no org_id and GetEnabledRiskPolicies read it with no predicate:
//
//	SELECT ... FROM risk_policies WHERE enabled = true ORDER BY priority ASC
//
// AssessLoginRisk applies EVERY returned policy that matches, so every
// organization's rules were evaluated against every organization's logins.
//
// The direction is what makes it sharp. applyRiskPolicyActions REPLACES the
// allowed-factor list rather than merging it, and the condition need not be
// clever: `risk_score_min: 0` is `assessment.Score >= 0`, true on every login
// ever assessed. So one row in one tenant, and every tenant's step-up admits an
// SMS code — or, with `deny: true`, every tenant's logins are refused.
func TestRiskPolicies_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('risk-b','risk-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// A policy that matches every login and hands back the weakest possible
	// answer: allow any factor, and deny nothing so the assertion is about the
	// factor list rather than a refusal.
	seedPolicy := func(org, name, conditions, actions string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO risk_policies (org_id, name, enabled, priority, conditions, actions)
			VALUES ($1::uuid, $2, true, 1, $3::jsonb, $4::jsonb)`,
			org, name+"-"+suffix, conditions, actions); err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
	}

	s := &Service{
		db:     db,
		logger: zap.NewNop(),
		cfg: &config.Config{AdaptiveMFA: config.AdaptiveMFAConfig{
			Enabled:              true,
			NewDeviceRiskScore:   30,
			FailedLoginRiskScore: 10,
			LowRiskThreshold:     30,
			MediumRiskThreshold:  50,
			HighRiskThreshold:    70,
		}},
	}

	loginCtx := func() *LoginContext {
		return &LoginContext{
			UserID:      "00000000-0000-0000-0000-0000000000a1",
			Username:    "risk-user",
			IPAddress:   "198.51.100.4",
			UserAgent:   "test",
			KnownDevice: true,
		}
	}
	hasMethod := func(methods []string, want string) bool {
		for _, m := range methods {
			if m == want {
				return true
			}
		}
		return false
	}

	// THE WEAKENING.
	t.Run("another tenant's policy cannot widen the allowed factors", func(t *testing.T) {
		seedPolicy(orgB, "b-allow-any",
			`{"risk_score_min": 0}`, `{"mfa_methods": ["webauthn"]}`)

		got, err := s.AssessLoginRisk(orgctx.With(ctx, orgctx.Org{ID: orgA}), loginCtx())
		if err != nil {
			t.Fatalf("org A assessment: %v", err)
		}
		// Org B's policy sets the list to exactly ["webauthn"]. If org A's
		// assessment comes back with that list, org B's rule was applied to org
		// A's login — and the same mechanism run the other way (mfa_methods
		// ["any"] against a high-risk assessment restricted to webauthn+push)
		// is what puts SMS back into another tenant's step-up.
		if len(got.AllowedMethods) == 1 && got.AllowedMethods[0] == "webauthn" {
			t.Fatalf("org B's risk policy set org A's allowed factors to %v. "+
				"applyRiskPolicyActions REPLACES this list, and risk_score_min 0 matches every "+
				"login ever assessed, so one row in one tenant rewrites the second-factor rule "+
				"for every tenant on the installation", got.AllowedMethods)
		}
	})

	// THE REFUSAL.
	t.Run("another tenant's policy cannot deny the login", func(t *testing.T) {
		seedPolicy(orgB, "b-deny", `{"risk_score_min": 0}`, `{"deny": true}`)

		got, err := s.AssessLoginRisk(orgctx.With(ctx, orgctx.Org{ID: orgA}), loginCtx())
		if err != nil {
			t.Fatalf("org A assessment: %v", err)
		}
		if got.DenyAccess {
			t.Fatal("org B's risk policy denied an org A login. One row with an always-true " +
				"condition refuses every login on the installation")
		}
	})

	// The predicate must scope, not empty: a tenant's own policies still apply.
	t.Run("a tenant's own policy still applies", func(t *testing.T) {
		seedPolicy(orgA, "a-require-sms", `{"risk_score_min": 0}`,
			`{"require_mfa": true, "mfa_methods": ["sms"]}`)

		got, err := s.AssessLoginRisk(orgctx.With(ctx, orgctx.Org{ID: orgA}), loginCtx())
		if err != nil {
			t.Fatalf("org A assessment: %v", err)
		}
		if !hasMethod(got.AllowedMethods, "sms") || len(got.AllowedMethods) != 1 {
			t.Fatalf("org A's OWN policy did not apply: allowed factors %v. The org predicate "+
				"must scope the read, not empty it — a login path that silently loses its "+
				"policies is a login path with no adaptive MFA at all", got.AllowedMethods)
		}
		// NOT asserted here: that require_mfa took effect. applyRiskPolicyActions
		// sets it, and then step 7's threshold switch reassigns RequiresMFA
		// unconditionally in the low and medium branches — so a policy's
		// require_mfa only survives when the score already put the login above
		// the low threshold. That is a real observation about this code and it
		// is not a tenant-scoping defect, so it is written up rather than
		// changed here. AllowedMethods is not touched by the low branch, which
		// is why the assertion above is the one that proves the policy applied.

		// And org B is unaffected in the other direction.
		gotB, err := s.AssessLoginRisk(orgctx.With(ctx, orgctx.Org{ID: orgB}), loginCtx())
		if err != nil {
			t.Fatalf("org B assessment: %v", err)
		}
		if len(gotB.AllowedMethods) == 1 && gotB.AllowedMethods[0] == "sms" {
			t.Fatal("org A's policy applied to an org B login")
		}
	})

	// The direction of a failure. Losing the policies must not be quieter than
	// having them: a policy may MANDATE a factor, so a lookup that cannot
	// resolve its organization has to be an error the caller degrades on, not
	// an unfiltered read and not a silent empty set.
	t.Run("no organization is an error, not an unfiltered read", func(t *testing.T) {
		if _, err := s.GetEnabledRiskPolicies(ctx); err == nil {
			t.Fatal("GetEnabledRiskPolicies returned policies for a context with no " +
				"organization; with no tenant to scope by, the only safe answers are an error " +
				"(which AssessLoginRisk degrades to requiring MFA) or nothing at all — never " +
				"every tenant's rules")
		}
	})
}
