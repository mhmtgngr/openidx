package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Launching a privileged session asked nothing of the person holding the
// laptop beyond the sign-in they did that morning.
//
// The product has been able to demand a fresh factor mid-session since
// /oauth/stepup-* shipped, and nothing ever demanded one: the step_up JWT
// those endpoints mint is read by no handler, no middleware and no gate. So a
// laptop that authenticated at 09:00 could open an RDP session to a domain
// controller at 19:00, or reveal a stored credential, with the same silence.
//
// These cases pin the gate at the PAM half. The admin-write half hangs off
// requireAdminRole and is pinned in TestAdminWritesNeedAFreshFactor below.

const stepupOrg = devOrg

var stepupSchema = []string{
	`CREATE TABLE IF NOT EXISTS sessions (
		id UUID PRIMARY KEY, user_id UUID, org_id UUID,
		client_id VARCHAR(255), started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ, auth_methods TEXT[], mfa_verified_at TIMESTAMPTZ)`,
	`CREATE TABLE IF NOT EXISTS system_settings (
		key VARCHAR(255) PRIMARY KEY, value JSONB NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
}

// stepupService builds a Service with the gate configured, over a real DB.
func stepupService(t *testing.T, gate string, maxAge time.Duration) (*Service, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: stepupOrg})
	for _, stmt := range stepupSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			cleanup()
			t.Fatalf("schema: %v", err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `DELETE FROM sessions`); err != nil {
		cleanup()
		t.Fatalf("clear sessions: %v", err)
	}
	svc := &Service{
		db:     db,
		logger: zap.NewNop(),
		config: &config.Config{
			Environment:  "production",
			StepUpGate:   gate,
			StepUpMaxAge: maxAge,
		},
	}
	return svc, ctx, cleanup
}

// seedSession inserts a login session whose factor was verified `ago` in the
// past. A negative `ago` means the session has never proved a second factor.
func seedSession(t *testing.T, svc *Service, ctx context.Context, id, userID string, ago time.Duration) {
	t.Helper()
	var verified any
	if ago >= 0 {
		verified = time.Now().Add(-ago)
	}
	if _, err := svc.db.Pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, org_id, client_id, expires_at, mfa_verified_at)
		 VALUES ($1, $2, $3, 'openidx-console', NOW() + INTERVAL '1 day', $4)`,
		id, userID, stepupOrg, verified); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

// driveGate runs one request through the gate with the given gin-context
// identity, and returns the recorder.
func driveGate(svc *Service, ctx context.Context, method string, set map[string]any) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	handler := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"launched": true}) }
	inject := func(c *gin.Context) {
		c.Request = c.Request.WithContext(ctx)
		for k, v := range set {
			c.Set(k, v)
		}
		c.Next()
	}
	r.Handle(method, "/pam/entries/:id/connect", inject, svc.requireFreshMFA("pam.connect"), handler)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, "/pam/entries/e1/connect", nil))
	return w
}

func TestPamLaunchNeedsAFreshFactor(t *testing.T) {
	const (
		freshSID = "11111111-2222-3333-4444-555555555501"
		staleSID = "11111111-2222-3333-4444-555555555502"
		neverSID = "11111111-2222-3333-4444-555555555503"
		userID   = "11111111-2222-3333-4444-5555555555aa"
	)

	for _, tc := range []struct {
		name string
		gate string
		sid  string
		want int
	}{
		// Off is the default and changes nothing, which is what makes the
		// migration safe to ship ahead of the rollout.
		{"off: a stale session launches, as it always has", "off", staleSID, http.StatusOK},

		// Observe records and permits: this is the mode an operator runs to
		// find out how often the window would interrupt real work.
		{"observe: a stale session still launches", "observe", staleSID, http.StatusOK},

		{"enforce: a fresh factor launches", "enforce", freshSID, http.StatusOK},
		{"enforce: a stale factor is refused", "enforce", staleSID, http.StatusForbidden},
		// An org whose login policy does not require MFA produces these and
		// nothing else. Refusing is right — the gate cannot invent a factor —
		// and the reason has to say so, because the fix is the login policy.
		{"enforce: a session that never proved a factor is refused", "enforce", neverSID, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, ctx, cleanup := stepupService(t, tc.gate, 15*time.Minute)
			defer cleanup()
			seedSession(t, svc, ctx, freshSID, userID, 1*time.Minute)
			seedSession(t, svc, ctx, staleSID, userID, 2*time.Hour)
			seedSession(t, svc, ctx, neverSID, userID, -1)

			w := driveGate(svc, ctx, http.MethodPost, map[string]any{
				"user_id":    userID,
				"org_id":     stepupOrg,
				"session_id": tc.sid,
			})
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestARefusalNamesTheWayOut. A 403 that only says no leaves a user with a
// legitimate need and no route to it, and leaves the console with nothing to
// distinguish "you may never do this" from "do this again in ten seconds".
func TestARefusalNamesTheWayOut(t *testing.T) {
	svc, ctx, cleanup := stepupService(t, "enforce", 15*time.Minute)
	defer cleanup()
	const sid = "11111111-2222-3333-4444-555555555511"
	seedSession(t, svc, ctx, sid, "11111111-2222-3333-4444-5555555555aa", 2*time.Hour)

	w := driveGate(svc, ctx, http.MethodPost, map[string]any{
		"user_id":    "11111111-2222-3333-4444-5555555555aa",
		"org_id":     stepupOrg,
		"session_id": sid,
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal is not JSON: %v", err)
	}
	if body["error"] != "step_up_required" {
		t.Errorf("error = %v, want step_up_required — the console keys its dialog off this", body["error"])
	}
	if body["challenge_url"] != "/oauth/stepup-challenge" {
		t.Errorf("challenge_url = %v; a refusal must name the endpoint that clears it", body["challenge_url"])
	}
	if body["reason"] != "stale" {
		t.Errorf("reason = %v, want stale", body["reason"])
	}
	if body["max_age_seconds"] != float64(900) {
		t.Errorf("max_age_seconds = %v, want 900", body["max_age_seconds"])
	}
}

// TestMachineCallersLaunchWithoutAFactor: an unattended integration has nobody
// to prompt. Gating it would not produce a step-up, it would produce a 403 at
// 03:00 that nothing can clear.
func TestMachineCallersLaunchWithoutAFactor(t *testing.T) {
	svc, ctx, cleanup := stepupService(t, "enforce", 15*time.Minute)
	defer cleanup()

	for _, tc := range []struct {
		name string
		set  map[string]any
	}{
		{"api key", map[string]any{"user_id": "u1", "org_id": stepupOrg, "auth_method": "api_key"}},
		{"service account", map[string]any{"user_id": "u1", "org_id": stepupOrg, "service_account_id": "sa1"}},
		{"client-credentials token, no subject", map[string]any{"org_id": stepupOrg}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := driveGate(svc, ctx, http.MethodPost, tc.set); w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
		})
	}
}

// TestTheConsoleWindowWins gives security.reauth_interval its first reader.
// The setting has existed in three places — a v63 column, the settings
// document, and SessionPolicy.ReauthInterval — and been consulted by nothing.
func TestTheConsoleWindowWins(t *testing.T) {
	svc, ctx, cleanup := stepupService(t, "enforce", 15*time.Minute)
	defer cleanup()
	const sid = "11111111-2222-3333-4444-555555555521"
	const userID = "11111111-2222-3333-4444-5555555555aa"
	// Six minutes old: inside the 15-minute deployment default...
	seedSession(t, svc, ctx, sid, userID, 6*time.Minute)

	set := map[string]any{"user_id": userID, "org_id": stepupOrg, "session_id": sid}
	if w := driveGate(svc, ctx, http.MethodPost, set); w.Code != http.StatusOK {
		t.Fatalf("with the default window: status = %d, want 200", w.Code)
	}

	// ...and outside a 5-minute window an operator sets on the console.
	if _, err := svc.db.Pool.Exec(ctx,
		`INSERT INTO system_settings (key, value) VALUES ('system', $1)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		`{"security":{"reauth_interval":300}}`); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if w := driveGate(svc, ctx, http.MethodPost, set); w.Code != http.StatusForbidden {
		t.Fatalf("with reauth_interval=300: status = %d, want 403 — the console setting is not being read", w.Code)
	}
}

// TestAdminWritesNeedAFreshFactor pins the second enforcement point, and the
// carve-out that keeps a console usable: reads are never gated.
func TestAdminWritesNeedAFreshFactor(t *testing.T) {
	const (
		freshSID = "11111111-2222-3333-4444-555555555531"
		staleSID = "11111111-2222-3333-4444-555555555532"
		userID   = "11111111-2222-3333-4444-5555555555bb"
	)

	for _, tc := range []struct {
		name   string
		method string
		sid    string
		roles  []string
		want   int
	}{
		{"a read is never gated, however old the factor", http.MethodGet, staleSID, []string{"admin"}, http.StatusOK},
		{"a write with a fresh factor proceeds", http.MethodPost, freshSID, []string{"admin"}, http.StatusOK},
		{"a write with a stale factor is refused", http.MethodPost, staleSID, []string{"admin"}, http.StatusForbidden},
		{"a delete with a stale factor is refused", http.MethodDelete, staleSID, []string{"super_admin"}, http.StatusForbidden},
		// The role gate still decides first: a non-admin gets the 403 it
		// always got, for the reason it always got, not a step-up prompt.
		{"a non-admin is still refused on roles", http.MethodPost, freshSID, []string{"user"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, ctx, cleanup := stepupService(t, "enforce", 15*time.Minute)
			defer cleanup()
			seedSession(t, svc, ctx, freshSID, userID, 1*time.Minute)
			seedSession(t, svc, ctx, staleSID, userID, 2*time.Hour)

			gin.SetMode(gin.TestMode)
			r := gin.New()
			inject := func(c *gin.Context) {
				c.Request = c.Request.WithContext(ctx)
				c.Set("user_id", userID)
				c.Set("org_id", stepupOrg)
				c.Set("session_id", tc.sid)
				c.Set("roles", tc.roles)
				c.Next()
			}
			r.Handle(tc.method, "/ziti/settings", inject, svc.requireAdminRole(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"ok": true})
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, "/ziti/settings", nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestTheGateFailsClosedWhenTheSessionCannotBeRead. The gate an operator turns
// on to lock something down must not come open when the database will not
// answer — that is precisely the moment an attacker would want it to. The
// assignment gate was changed for this reason in P5; this follows it.
func TestTheGateFailsClosedWhenTheSessionCannotBeRead(t *testing.T) {
	svc, ctx, cleanup := stepupService(t, "enforce", 15*time.Minute)
	defer cleanup()

	// Remove the column the gate reads, so the query errors rather than
	// returning no rows: "cannot be read" is a different state from "absent".
	if _, err := svc.db.Pool.Exec(ctx, `ALTER TABLE sessions DROP COLUMN mfa_verified_at`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	defer func() {
		_, _ = svc.db.Pool.Exec(ctx, `ALTER TABLE sessions ADD COLUMN mfa_verified_at TIMESTAMPTZ`)
	}()

	w := driveGate(svc, ctx, http.MethodPost, map[string]any{
		"user_id":    "11111111-2222-3333-4444-5555555555aa",
		"org_id":     stepupOrg,
		"session_id": "11111111-2222-3333-4444-555555555541",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a failed lookup came open under enforce", w.Code)
	}
}
