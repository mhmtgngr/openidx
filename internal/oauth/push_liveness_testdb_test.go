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

// The administrator lockout, at the login decision, against the migrated
// schema and the real identity service: push was the user's only factor, the
// phone was gone, and the login offered push and nothing else.
//
// With the phone unseen for longer than PUSH_DEVICE_STALE_DAYS the login still
// challenges (never lets the password alone through) but offers the bypass
// code first and says the phone has not been seen. Once the sweep has
// disabled the phone the user is STILL challenged — a disabled phone is a
// factor they have, not one they lost — with only the fallbacks.
func TestPushOnlyUserWithADeadPhoneIsChallengedWithFallbacks(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010"
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := &identity.User{UserName: "push-only-" + suffix}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, user.UserName, user.UserName+"@example.test").Scan(&user.ID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	var deviceID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO mfa_push_devices (user_id, device_token, platform, device_name, enabled, org_id, created_at, last_seen_at)
		VALUES ($1::uuid, $2, 'android', 'Lost phone', true, $3::uuid, NOW() - interval '200 days', NOW() - interval '45 days')
		RETURNING id::text`,
		user.ID, "ntfy:"+suffix, org).Scan(&deviceID); err != nil {
		t.Fatalf("seed push device: %v", err)
	}
	// An enabled policy that accepts any factor, so the login is challenged
	// whatever risk says (adaptive MFA is off in this config).
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ($1, '', true, 100, '{}', '[]', 0, $2::uuid)`, "everyone-"+suffix, org); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	cfg := &config.Config{}
	cfg.PushMFA.Enabled = true
	cfg.PushMFA.StaleDeviceDays = 30
	s := &Service{db: db, config: cfg, logger: zap.NewNop(),
		identityService: identity.NewService(db, nil, cfg, zap.NewNop())}
	decide := func() mfaEvaluation {
		t.Helper()
		return s.evaluateMFA(orgCtx, user, "203.0.113.7", "evidence-run", "", "", false, 0, nil)
	}

	t.Run("phone unseen: challenged, bypass first, push last, notice", func(t *testing.T) {
		ev := decide()
		if !ev.Enabled || !ev.Challenge {
			t.Fatalf("a push-only user must be challenged: %+v", ev)
		}
		if len(ev.Methods) < 2 || ev.Methods[0] != "bypass" || ev.Methods[len(ev.Methods)-1] != "push" {
			t.Fatalf("methods = %v, want the bypass code first and push last", ev.Methods)
		}
		if ev.PushUnseen == nil || ev.PushUnseen.Disabled || ev.PushUnseen.StaleDays != 30 {
			t.Fatalf("notice = %+v, want an unseen (not disabled) phone with a 30-day window", ev.PushUnseen)
		}
	})

	t.Run("phone seen again: push alone, no notice", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `UPDATE mfa_push_devices SET last_seen_at = NOW() WHERE id = $1::uuid`, deviceID); err != nil {
			t.Fatal(err)
		}
		ev := decide()
		if ev.PushUnseen != nil || len(ev.Methods) != 1 || ev.Methods[0] != "push" {
			t.Fatalf("a phone seen today must be offered as before: methods=%v notice=%+v", ev.Methods, ev.PushUnseen)
		}
	})

	t.Run("phone disabled by the sweep: still challenged, with the fallbacks", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `
			UPDATE mfa_push_devices SET enabled = false, disabled_at = NOW(), disabled_reason = 'stale',
			       last_seen_at = NOW() - interval '100 days' WHERE id = $1::uuid`, deviceID); err != nil {
			t.Fatal(err)
		}
		ev := decide()
		if !ev.Enabled || !ev.Challenge {
			t.Fatalf("disabling the phone must not drop the second factor: %+v", ev)
		}
		if len(ev.Methods) != 1 || ev.Methods[0] != "bypass" {
			t.Fatalf("methods = %v, want only the bypass code", ev.Methods)
		}
		if ev.PushUnseen == nil || !ev.PushUnseen.Disabled {
			t.Fatalf("notice = %+v, want a disabled phone", ev.PushUnseen)
		}
	})
}
