package identity

import (
	"context"
	"errors"
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
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
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
		required, _, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
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
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
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

	// The console lists policies lowest priority number first ("lower =
	// first"), then by name, and the policy it lists first is the one that
	// decides: which policy matched is observable once a policy can require
	// particular methods.
	t.Run("the policy the console lists first wins", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('later', true, 99, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if policy == nil || policy.Name != "always" {
			t.Errorf("got %+v, want the priority-5 policy, which the console lists before priority 99", policy)
		}

		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('aardvark', true, 5, '{"factor_enrolled":true}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, policy, err = svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if policy == nil || policy.Name != "aardvark" {
			t.Errorf("got %+v, want the policy named first among equal priorities", policy)
		}
	})

	// A groups condition scopes a policy to members of the named groups: the
	// admin API accepts it (internal/admin/mfa_policy_conditions.go), and the
	// evaluator matches the names of the user's groups. Everything else in
	// this test matched because factor_enrolled is not read; this is the one
	// condition that is.
	t.Run("a policy scoped to groups applies only to their members", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `DELETE FROM mfa_policies WHERE org_id = $1`, org); err != nil {
			t.Fatalf("clear policies: %v", err)
		}
		for _, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS groups (id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT,
				parent_id UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				org_id UUID NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS group_memberships (group_id UUID NOT NULL, user_id UUID NOT NULL,
				joined_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID NOT NULL, expires_at TIMESTAMPTZ, PRIMARY KEY (user_id, group_id))`,
			`INSERT INTO groups (id, name, org_id) VALUES ('33333333-0000-0000-0000-0000000000d1', 'Finance', '` + org + `')`,
			`INSERT INTO mfa_policies (name, enabled, priority, conditions, required_methods, org_id)
				VALUES ('finance', true, 1, '{"groups":["Finance"]}', '["totp"]', '` + org + `')`,
		} {
			if _, err := db.Pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("seed: %v\n%s", err, stmt)
			}
		}
		required, _, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Fatal("a user outside the policy's groups was challenged by it")
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO group_memberships (group_id, user_id, org_id)
			VALUES ('33333333-0000-0000-0000-0000000000d1', $1, $2)`, user, org); err != nil {
			t.Fatalf("join group: %v", err)
		}
		required, policy, err := svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if !required || policy == nil || policy.Name != "finance" {
			t.Fatalf("got (%v, %+v), want the finance policy once the user is a member", required, policy)
		}

		// Memberships that cannot be read decide nothing: the evaluator says
		// so instead of answering "not a member" (a waiver for members) or
		// falling through to a lower policy (the wrong one for them).
		if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
			VALUES ('everyone', true, 9, '{}', $1)`, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := db.Pool.Exec(ctx, `DROP TABLE group_memberships`); err != nil {
			t.Fatalf("drop memberships: %v", err)
		}
		required, policy, err = svc.IsMFARequired(ctx, user, "1.2.3.4", SignInContext{})
		if !errors.Is(err, ErrMFAPolicyUndecidable) {
			t.Fatalf("got (%v, %+v, %v), want ErrMFAPolicyUndecidable when membership cannot be read", required, policy, err)
		}
		if required || policy != nil {
			t.Fatalf("got (%v, %+v) with the error, want no policy chosen", required, policy)
		}
	})

	t.Run("another org's policy does not apply", func(t *testing.T) {
		otherCtx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-0000000000d9"})
		required, _, err := svc.IsMFARequired(otherCtx, user, "1.2.3.4", SignInContext{})
		if err != nil {
			t.Fatalf("IsMFARequired: %v", err)
		}
		if required {
			t.Error("policies must not leak across orgs")
		}
	})

	// Population and sign-in conditions: user_types and vendor_org_ids read
	// the user row, idp_ids and client_ids the SignInContext. A sign-in that
	// lacks the context never satisfies the condition, and is never
	// undecidable for it.
	t.Run("population and sign-in conditions", func(t *testing.T) {
		const vendor = "44444444-0000-0000-0000-0000000000d1"
		const idp = "55555555-0000-0000-0000-0000000000d1"
		for _, stmt := range []string{
			`DELETE FROM mfa_policies WHERE org_id = '` + org + `'`,
			`CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, org_id UUID NOT NULL, user_type TEXT, vendor_org_id UUID)`,
			`INSERT INTO users (id, org_id, user_type, vendor_org_id) VALUES ('` + user + `', '` + org + `', 'external', '` + vendor + `')
				ON CONFLICT (id) DO UPDATE SET user_type = 'external', vendor_org_id = '` + vendor + `'`,
		} {
			if _, err := db.Pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("seed %q: %v", stmt, err)
			}
		}
		cases := []struct {
			name, conds string
			signIn      SignInContext
			want        bool
		}{
			{"user type matches", `{"user_types":["external"]}`, SignInContext{}, true},
			{"user type does not match", `{"user_types":["internal","service"]}`, SignInContext{}, false},
			{"partner org matches", `{"vendor_org_ids":["` + vendor + `"]}`, SignInContext{}, true},
			{"partner org does not match", `{"vendor_org_ids":["44444444-0000-0000-0000-0000000000ff"]}`, SignInContext{}, false},
			{"idp matches", `{"idp_ids":["` + idp + `"]}`, SignInContext{IdPID: idp}, true},
			{"no idp on the sign-in", `{"idp_ids":["` + idp + `"]}`, SignInContext{}, false},
			{"client matches", `{"client_ids":["admin-console"]}`, SignInContext{ClientID: "admin-console"}, true},
			{"other client", `{"client_ids":["admin-console"]}`, SignInContext{ClientID: "portal"}, false},
			{"no client on the sign-in", `{"client_ids":["admin-console"]}`, SignInContext{}, false},
			{"all four must match", `{"user_types":["external"],"vendor_org_ids":["` + vendor + `"],"idp_ids":["` + idp + `"],"client_ids":["portal"]}`,
				SignInContext{IdPID: idp, ClientID: "portal"}, true},
			{"one of four fails", `{"user_types":["external"],"vendor_org_ids":["` + vendor + `"],"idp_ids":["` + idp + `"],"client_ids":["portal"]}`,
				SignInContext{IdPID: idp, ClientID: "admin-console"}, false},
		}
		for _, tc := range cases {
			if _, err := db.Pool.Exec(ctx, `DELETE FROM mfa_policies WHERE org_id = $1`, org); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_policies (name, enabled, priority, conditions, org_id)
				VALUES ('scoped', true, 1, $1::jsonb, $2)`, tc.conds, org); err != nil {
				t.Fatalf("%s: seed: %v", tc.name, err)
			}
			required, _, err := svc.IsMFARequired(ctx, user, "1.2.3.4", tc.signIn)
			if err != nil {
				t.Fatalf("%s: IsMFARequired: %v", tc.name, err)
			}
			if required != tc.want {
				t.Errorf("%s: required = %v, want %v", tc.name, required, tc.want)
			}
		}
	})
}
