package identity

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The system-wide passwordless settings, tested because they used to decide
// nothing.
//
// PasswordlessSystemSettings was saved by PUT /identity/passwordless/settings,
// read back by its own GET, and consulted by no other code in the tree. An
// administrator who turned magic links off for the organization still got magic
// links, because CreateMagicLink asked only the PER-USER preference — a
// different struct, in a different table, set by the user themselves. The
// stronger switch was the one that did nothing.
//
// tools/inertswitch found require_device_trust on that struct; these are its
// siblings, which the census's same-package name suppression hides behind the
// per-user fields that ARE decided.
func passwordlessTestService(t *testing.T) (*Service, context.Context, string, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, "", func() {}
	}

	ctx := context.Background()
	orgID := uuid.New().String()
	for _, stmt := range []string{
		`CREATE TABLE system_settings (key TEXT PRIMARY KEY, value JSONB NOT NULL)`,
		`CREATE TABLE users (id UUID PRIMARY KEY, email TEXT, enabled BOOLEAN DEFAULT true, org_id UUID)`,
		`CREATE TABLE passwordless_preferences (
			id UUID PRIMARY KEY, user_id UUID, webauthn_only BOOLEAN DEFAULT false,
			magic_link_enabled BOOLEAN DEFAULT true, qr_login_enabled BOOLEAN DEFAULT true,
			preferred_method TEXT DEFAULT 'webauthn',
			created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID)`,
		`CREATE TABLE magic_links (
			id UUID PRIMARY KEY, org_id UUID, user_id UUID, email TEXT, token_hash TEXT,
			purpose TEXT, redirect_url TEXT, ip_address TEXT, user_agent TEXT,
			status TEXT, created_at TIMESTAMPTZ DEFAULT now(), expires_at TIMESTAMPTZ,
			used_at TIMESTAMPTZ)`,
		`CREATE TABLE qr_login_sessions (
			id UUID PRIMARY KEY, session_token TEXT, qr_code_data TEXT, status TEXT,
			user_id UUID, browser_info JSONB, mobile_info JSONB, ip_address TEXT,
			created_at TIMESTAMPTZ DEFAULT now(), expires_at TIMESTAMPTZ,
			scanned_at TIMESTAMPTZ, approved_at TIMESTAMPTZ, org_id UUID)`,
	} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			cleanup()
			t.Fatalf("fixture: %v (%s)", err, stmt)
		}
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, email, enabled, org_id) VALUES ($1, 'vendor@example.test', true, $2)`,
		uuid.New().String(), orgID); err != nil {
		cleanup()
		t.Fatalf("seed user: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	return s, orgctx.With(ctx, orgctx.Org{ID: orgID}), orgID, cleanup
}

func setPasswordlessSettings(t *testing.T, s *Service, ctx context.Context, in PasswordlessSystemSettings) {
	t.Helper()
	if err := s.savePasswordlessSettings(ctx, in); err != nil {
		t.Fatalf("save settings: %v", err)
	}
}

// TestTheOrganizationSwitchStopsAMagicLink is the whole point: an administrator
// turns the method off and it is off, without touching a single user's
// preferences.
func TestTheOrganizationSwitchStopsAMagicLink(t *testing.T) {
	s, ctx, _, cleanup := passwordlessTestService(t)
	if s == nil {
		return
	}
	defer cleanup()

	on := defaultPasswordlessSettings()
	setPasswordlessSettings(t, s, ctx, on)
	if _, err := s.CreateMagicLink(ctx, "vendor@example.test", "login", "", "203.0.113.9", "test"); err != nil {
		t.Fatalf("with magic links enabled the link must be minted: %v", err)
	}

	off := defaultPasswordlessSettings()
	off.MagicLinkEnabled = false
	setPasswordlessSettings(t, s, ctx, off)

	_, err := s.CreateMagicLink(ctx, "vendor@example.test", "login", "", "203.0.113.9", "test")
	if err == nil {
		t.Fatal("magic_link_enabled=false and a link was minted anyway. That was the state for " +
			"the whole life of this endpoint: the setting was stored, returned on the next GET, " +
			"and asked by nothing.")
	}
	if !strings.Contains(err.Error(), "organization") {
		t.Errorf("the refusal blames the wrong party: %v. A user whose own preference is intact "+
			"must not be told their account disabled the method.", err)
	}
}

// TestTheOrganizationSwitchStopsQRLogin. Same claim, the other method — and the
// session is refused before it is minted rather than at scan time, because the
// browser showing the code has no user yet and would otherwise display a QR
// code that can never complete.
func TestTheOrganizationSwitchStopsQRLogin(t *testing.T) {
	s, ctx, _, cleanup := passwordlessTestService(t)
	if s == nil {
		return
	}
	defer cleanup()

	setPasswordlessSettings(t, s, ctx, defaultPasswordlessSettings())
	if _, err := s.CreateQRLoginSession(ctx, "203.0.113.9", map[string]interface{}{"ua": "test"}); err != nil {
		t.Fatalf("with QR login enabled the session must be created: %v", err)
	}

	off := defaultPasswordlessSettings()
	off.QRLoginEnabled = false
	setPasswordlessSettings(t, s, ctx, off)

	if _, err := s.CreateQRLoginSession(ctx, "203.0.113.9", map[string]interface{}{"ua": "test"}); err == nil {
		t.Fatal("qr_login_enabled=false and a session was created anyway")
	}
}

// TestTheStoredExpiryIsTheExpiryUsed. magic_link_expiry_minutes sat in the
// settings blob next to `time.Now().Add(15 * time.Minute)`: a number an
// administrator could set to five and a link that lived fifteen.
func TestTheStoredExpiryIsTheExpiryUsed(t *testing.T) {
	s, ctx, _, cleanup := passwordlessTestService(t)
	if s == nil {
		return
	}
	defer cleanup()

	in := defaultPasswordlessSettings()
	in.MagicLinkExpiryMinutes = 2
	setPasswordlessSettings(t, s, ctx, in)

	link, err := s.CreateMagicLink(ctx, "vendor@example.test", "login", "", "203.0.113.9", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	lifetime := link.ExpiresAt.Sub(link.CreatedAt)
	if lifetime > 3*time.Minute || lifetime < time.Minute {
		t.Errorf("the link lives %v; magic_link_expiry_minutes says 2. The setting was stored "+
			"beside a hardcoded fifteen minutes.", lifetime)
	}
}

// TestTheHourlyCapIsEnforced. max_magic_links_per_hour defaulted to 5 and
// limited nothing, so the setting named a rate limit that did not exist.
func TestTheHourlyCapIsEnforced(t *testing.T) {
	s, ctx, _, cleanup := passwordlessTestService(t)
	if s == nil {
		return
	}
	defer cleanup()

	in := defaultPasswordlessSettings()
	in.MaxMagicLinksPerHour = 2
	setPasswordlessSettings(t, s, ctx, in)

	for i := 0; i < 2; i++ {
		if _, err := s.CreateMagicLink(ctx, "vendor@example.test", "login", "", "203.0.113.9", "test"); err != nil {
			t.Fatalf("link %d of the allowance was refused: %v", i+1, err)
		}
	}
	if _, err := s.CreateMagicLink(ctx, "vendor@example.test", "login", "", "203.0.113.9", "test"); err == nil {
		t.Error("a third link was minted with max_magic_links_per_hour=2. An unlimited supply of " +
			"single-use sign-in credentials to one mailbox is the shape of a mailbox-access " +
			"attack, which is the reason the setting exists.")
	}
}

// TestNoUnenforceableSwitchSurvives. Two fields were removed rather than wired,
// because neither named an enforcement point this endpoint owns:
// biometric_only_enabled duplicated two per-user settings that are already
// enforced, with no rule for which wins; require_device_trust named a control
// that exists elsewhere (POSTURE_DEVICE_TRUST_GATE) with a posture service
// behind it. Either coming back unwired would put the operator back where they
// started.
func TestNoUnenforceableSwitchSurvives(t *testing.T) {
	for _, gone := range []string{"BiometricOnlyEnabled", "RequireDeviceTrust"} {
		if _, ok := reflect.TypeOf(PasswordlessSystemSettings{}).FieldByName(gone); ok {
			{
				t.Errorf("PasswordlessSystemSettings has %s again. If organization-scoped %s is "+
					"wanted, it needs an enforcement point and a rule for how it composes with "+
					"the per-user setting of the same name — not a second copy of the word.",
					gone, gone)
			}
		}
	}
}
