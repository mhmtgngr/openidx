package oauth

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/stepup"
)

// The two writers of sessions.mfa_verified_at (v186), which is the only fact
// the step-up freshness gate reads.
//
// The timestamp is derived from the auth methods recorded at login rather than
// written by a separate call at each login site. There are three such sites
// today (password login, MFA verify, force-login) and a fourth added later
// would otherwise record "mfa" in amr while leaving the session permanently
// stale: visibly authenticated with a second factor, and unable to prove it to
// the gate. These cases pin that derivation, and pin the other writer --
// /oauth/stepup-verify -- because before v1.34.0 the only output of a
// successful step-up was a JWT nothing read, so completing a challenge changed
// nothing at all.

const stampOrg = "00000000-0000-0000-0000-000000000010"

func stampFixture(t *testing.T) (*Service, context.Context, func()) {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: stampOrg})
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY, user_id UUID, org_id UUID, client_id VARCHAR(255),
			started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ,
			auth_methods TEXT[], mfa_verified_at TIMESTAMPTZ)`); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx, cleanup
}

func seedStampSession(t *testing.T, s *Service, ctx context.Context, id string) {
	t.Helper()
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, org_id, client_id, expires_at)
		 VALUES ($1, gen_random_uuid(), $2, 'openidx-console', NOW() + INTERVAL '1 day')`,
		id, stampOrg); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func readStamp(t *testing.T, s *Service, ctx context.Context, id string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT mfa_verified_at FROM sessions WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read stamp: %v", err)
	}
	return at
}

func TestRecordingASecondFactorStampsTheSession(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()

	for _, tc := range []struct {
		name    string
		id      string
		methods []string
		want    bool
	}{
		{"password only leaves it unstamped", "bbbbbbbb-0000-0000-0000-000000000001", []string{"pwd"}, false},
		{"a second factor stamps it", "bbbbbbbb-0000-0000-0000-000000000002", []string{"pwd", "mfa"}, true},
		// Order and company must not matter: the derivation is "does this
		// contain mfa", not "is this exactly [pwd mfa]".
		{"mfa in any position", "bbbbbbbb-0000-0000-0000-000000000003", []string{"mfa", "pwd", "hwk"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedStampSession(t, svc, ctx, tc.id)
			svc.recordSessionAuthMethods(ctx, tc.id, tc.methods)

			at := readStamp(t, svc, ctx, tc.id)
			if tc.want && at == nil {
				t.Fatal("auth_methods recorded a second factor and the session was left unstamped — " +
					"the gate would treat it as never verified")
			}
			if !tc.want && at != nil {
				t.Fatalf("a password-only login stamped mfa_verified_at (%v); the column would then "+
					"assert a factor that was never proved", *at)
			}
		})
	}
}

// TestASecondRecordingWithoutMFADoesNotClearTheStamp. The UPDATE writes both
// columns; a later call recording only ["pwd"] must not erase a factor the
// session really did verify, or a re-recorded session would silently go stale.
func TestASecondRecordingWithoutMFADoesNotClearTheStamp(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()

	const id = "bbbbbbbb-0000-0000-0000-000000000011"
	seedStampSession(t, svc, ctx, id)
	svc.recordSessionAuthMethods(ctx, id, []string{"pwd", "mfa"})
	first := readStamp(t, svc, ctx, id)
	if first == nil {
		t.Fatal("the first recording did not stamp")
	}

	svc.recordSessionAuthMethods(ctx, id, []string{"pwd"})
	second := readStamp(t, svc, ctx, id)
	if second == nil {
		t.Fatal("a later password-only recording cleared a factor the session did verify")
	}
	if !second.Equal(*first) {
		t.Errorf("the stamp moved on a recording that verified nothing: %v → %v", first, second)
	}
}

// TestStampRefreshesFreshness is the mechanism that lets a user get past the
// gate: stepup.Stamp is what /oauth/stepup-verify calls on success, and it has
// to make an old session current.
func TestStampRefreshesFreshness(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()

	const id = "bbbbbbbb-0000-0000-0000-000000000021"
	seedStampSession(t, svc, ctx, id)
	if _, err := svc.db.Pool.Exec(ctx,
		`UPDATE sessions SET mfa_verified_at = NOW() - INTERVAL '9 hours' WHERE id = $1`, id); err != nil {
		t.Fatalf("age the session: %v", err)
	}

	caller := stepup.Caller{UserID: "u1", OrgID: stampOrg, SessionID: id}
	if d := stepup.Gate(ctx, svc.db, stepup.ModeEnforce, 15*time.Minute, caller); d.Allowed {
		t.Fatal("a nine-hour-old factor passed a fifteen-minute window")
	}

	if err := stepup.Stamp(ctx, svc.db, stampOrg, id); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if d := stepup.Gate(ctx, svc.db, stepup.ModeEnforce, 15*time.Minute, caller); !d.Allowed {
		t.Fatalf("the session is still refused after a successful step-up (%+v) — answering a "+
			"challenge would change nothing, which is the defect this whole change closes", d)
	}
}

// TestStampIsScopedToTheOrg: the update carries a tenant predicate, so one
// tenant cannot refresh another tenant's session even given its id.
func TestStampIsScopedToTheOrg(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()

	const id = "bbbbbbbb-0000-0000-0000-000000000031"
	seedStampSession(t, svc, ctx, id)

	if err := stepup.Stamp(ctx, svc.db, "00000000-0000-0000-0000-0000000000ff", id); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if at := readStamp(t, svc, ctx, id); at != nil {
		t.Error("a stamp from another org landed on this session")
	}
}
