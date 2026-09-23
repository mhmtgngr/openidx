package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/migrations"
)

// The MFA policy row of docs/evidence/display-equals-enforcement.md at the login
// decision, against the migrated schema and the real identity service.
//
// A policy does one thing (#990): while it is enabled, a user with a second
// factor enrolled is challenged even when nothing else would challenge them.
// The user here has only email OTP, so TOTP does not force the challenge, and
// adaptive MFA is off, so risk does not either. With the policy on they are
// challenged; with it off, the same login is not. A user with no factor is never
// challenged by a policy, because requiring a factor they do not have would lock
// them out.
func TestMFAPolicyRaisesTheLoginChallenge(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name string) *identity.User {
		t.Helper()
		u := &identity.User{UserName: name + "-" + suffix}
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, u.UserName, u.UserName+"@example.test").Scan(&u.ID); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return u
	}
	withFactor := seedUser("mfa-email-otp")
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id)
		VALUES ($1::uuid, $2, true, $3::uuid)`,
		withFactor.ID, withFactor.UserName+"@example.test", org); err != nil {
		t.Fatalf("enroll email OTP: %v", err)
	}
	noFactor := seedUser("mfa-none")

	// The shape the admin API writes: no conditions, methods or grace period.
	var policyID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ($1, '', false, 100, '{}', '[]', 0, $2::uuid) RETURNING id::text`,
		"everyone-"+suffix, org).Scan(&policyID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	setPolicy := func(enabled bool) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx,
			`UPDATE mfa_policies SET enabled = $1 WHERE id = $2::uuid`, enabled, policyID); err != nil {
			t.Fatalf("set policy enabled=%v: %v", enabled, err)
		}
	}

	cfg := &config.Config{} // adaptive MFA off: risk never asks for the factor
	s := &Service{
		db:              db,
		config:          cfg,
		logger:          zap.NewNop(),
		identityService: identity.NewService(db, nil, cfg, zap.NewNop()),
	}
	decide := func(u *identity.User) mfaEvaluation {
		t.Helper()
		return s.evaluateMFA(orgCtx, u, "203.0.113.7", "evidence-run", "", "", false, 0, nil)
	}

	t.Run("policy off: the user with a factor is not challenged", func(t *testing.T) {
		setPolicy(false)
		ev := decide(withFactor)
		if !ev.Enabled {
			t.Fatalf("the enrolled email OTP factor was not seen: %+v", ev)
		}
		if ev.Challenge || ev.PolicyRequired {
			t.Fatalf("no policy is enabled and nothing else asks, yet the login is challenged: %+v", ev)
		}
	})
	t.Run("policy on: the same user is challenged, because of the policy", func(t *testing.T) {
		setPolicy(true)
		ev := decide(withFactor)
		if !ev.Challenge || !ev.PolicyRequired {
			t.Fatalf("an enabled policy must challenge a user with a factor: %+v", ev)
		}
	})
	t.Run("policy on: a user with no factor is not challenged", func(t *testing.T) {
		setPolicy(true)
		if ev := decide(noFactor); ev.Challenge {
			t.Fatalf("a policy must not demand a factor the user does not have: %+v", ev)
		}
	})
}
