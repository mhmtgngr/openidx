package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the admin console's own settings, migration v157.
//
// THE KEY WAS THE PRIMARY KEY. v62 declared admin_console_settings as
// `key TEXT PRIMARY KEY`, and the handler writes exactly four keys — general,
// security, authentication, branding — so the whole installation had four
// settings rows and every organization's administrators shared them. The read
// carried no predicate of any kind and the write was an upsert
// ON CONFLICT (key).
//
// The 'security' row is not decoration: it holds the password policy, and
// getPasswordPolicy reads it to answer POST /settings/validate-password. So one
// administrator lowering their minimum length, or turning "MFA required" off,
// did it for every tenant — and the check a password was measured against was
// whichever policy had been saved last, anywhere.
//
// This test lives in package admin rather than beside the handler because
// setupPAMTestDB resets the schema, and one package per database is the rule
// this suite keeps. Every method it drives is exported.
func TestAdminConsoleSettings_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
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
		`INSERT INTO organizations (name, slug) VALUES ('console-b','console-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	h := handlers.NewSettingsHandler(zap.NewNop(), db.Pool)

	call := func(handler gin.HandlerFunc, org, who, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", who)
		handler(c)
		return w
	}

	// A complete, valid payload: ValidateSettings insists on an organization
	// name, a support address, hex colours and sane session bounds before it
	// will store anything.
	payload := func(minLength int, requireSpecial, mfaRequired bool, domain string) string {
		s := handlers.Settings{
			General: handlers.GeneralSection{
				OrganizationName: "Org " + domain,
				SupportEmail:     "support@" + domain,
				DefaultLanguage:  "en",
				DefaultTimezone:  "UTC",
				SessionTimeout:   3600,
			},
			Security: handlers.SecuritySection{
				PasswordPolicy: handlers.PasswordPolicySettings{
					MinLength:        minLength,
					RequireUppercase: false,
					RequireLowercase: true,
					RequireNumbers:   false,
					RequireSpecial:   requireSpecial,
					MaxAge:           90,
					HistoryCount:     5,
				},
				MFA: handlers.MFASettings{
					Enabled:        true,
					Required:       mfaRequired,
					AllowedMethods: []string{"totp"},
				},
				Session: handlers.SessionSettings{
					IdleTimeoutMinutes:     30,
					AbsoluteTimeoutMinutes: 480,
					MaxConcurrentSessions:  5,
					RememberMeDays:         7,
				},
			},
			Auth: handlers.AuthSection{
				AllowedDomains: []string{domain},
				LockoutPolicy:  handlers.LockoutPolicy{Enabled: true, MaxFailedAttempts: 5, LockoutDuration: 15},
			},
			Branding: handlers.BrandingSection{
				PrimaryColor:   "#123456",
				SecondaryColor: "#654321",
				LoginPageTitle: "Sign in to " + domain,
			},
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal settings: %v", err)
		}
		return string(b)
	}

	// Org A is permissive, org B is strict. Before v157 the second save
	// overwrote the first for everybody.
	t.Run("each organization keeps its own console settings", func(t *testing.T) {
		if w := call(h.UpdateSettings, orgA, "admin-a", "PUT", "/settings",
			payload(8, false, false, "a.example.test")); w.Code != 200 {
			t.Fatalf("org A save: status %d, body %s", w.Code, w.Body.String())
		}
		if w := call(h.UpdateSettings, orgB, "admin-b", "PUT", "/settings",
			payload(20, true, true, "b.example.test")); w.Code != 200 {
			t.Fatalf("org B save: status %d, body %s", w.Code, w.Body.String())
		}

		read := func(org string) handlers.Settings {
			t.Helper()
			w := call(h.GetSettings, org, "admin", "GET", "/settings", "")
			if w.Code != 200 {
				t.Fatalf("read as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var out handlers.Settings
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return out
		}
		gotA, gotB := read(orgA), read(orgB)

		if gotA.Security.PasswordPolicy.MinLength != 8 || gotA.Security.MFA.Required {
			t.Errorf("org A read back org B's security settings: min_length=%d mfa_required=%v. "+
				"`key` was the PRIMARY KEY of admin_console_settings and both the read "+
				"and the upsert named it alone, so the installation had one 'security' "+
				"row and the last administrator to press Save chose the password policy "+
				"and the MFA requirement for every organization",
				gotA.Security.PasswordPolicy.MinLength, gotA.Security.MFA.Required)
		}
		if len(gotA.Auth.AllowedDomains) != 1 || gotA.Auth.AllowedDomains[0] != "a.example.test" {
			t.Errorf("org A's allowed sign-up domains are %v; org B chose them", gotA.Auth.AllowedDomains)
		}
		// And the predicate must scope, not empty: org B still has its own.
		if gotB.Security.PasswordPolicy.MinLength != 20 || !gotB.Security.MFA.Required {
			t.Errorf("org B lost its own settings: min_length=%d mfa_required=%v",
				gotB.Security.PasswordPolicy.MinLength, gotB.Security.MFA.Required)
		}
	})

	// The one read of this table that enforces rather than displays.
	t.Run("a password is checked against its own organization's policy", func(t *testing.T) {
		valid := func(org, password string) bool {
			t.Helper()
			w := call(h.ValidatePassword, org, "admin", "POST", "/settings/validate-password",
				fmt.Sprintf(`{"password":%q}`, password))
			if w.Code != 200 {
				t.Fatalf("validate as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var out struct {
				Valid bool `json:"valid"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return out.Valid
		}

		// Twelve lowercase letters, no special character: inside org A's policy
		// (minimum 8, no special required) and outside org B's (minimum 20,
		// special required).
		const password = "abcdefghijkl"
		if !valid(orgA, password) {
			t.Errorf("org A's own policy rejected a password that meets it")
		}
		if valid(orgB, password) {
			t.Error("org B accepted a password that fails its policy and passes org A's. " +
				"getPasswordPolicy read `WHERE key = 'security'` with no tenant term, " +
				"so the policy every password was measured against was whichever one " +
				"had been saved last, by an administrator of any organization")
		}
	})

	// Reset is a write like any other, and it used to reset the installation.
	t.Run("reset restores defaults for one organization only", func(t *testing.T) {
		if w := call(h.ResetSettings, orgA, "admin-a", "POST", "/settings/reset", ""); w.Code != 200 {
			t.Fatalf("org A reset: status %d, body %s", w.Code, w.Body.String())
		}
		w := call(h.GetSettings, orgB, "admin-b", "GET", "/settings", "")
		var gotB handlers.Settings
		if err := json.Unmarshal(w.Body.Bytes(), &gotB); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if gotB.Security.PasswordPolicy.MinLength != 20 {
			t.Errorf("org A's reset changed org B's password policy to min_length=%d",
				gotB.Security.PasswordPolicy.MinLength)
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal, not the shared row", func(t *testing.T) {
		for name, handler := range map[string]gin.HandlerFunc{
			"get":    h.GetSettings,
			"update": h.UpdateSettings,
			"reset":  h.ResetSettings,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/settings",
				bytes.NewBufferString(payload(12, true, true, "x.example.test"))) // bare context
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("roles", []string{"admin"})
			c.Set("user_id", "admin")
			handler(c)
			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}
	})

	// v62's read seeded UpdatedAt with time.Now() and then kept a stored row's
	// timestamp only if it was *later*, which no stored row can be.
	t.Run("the last-changed time is the last change, not the read", func(t *testing.T) {
		before := time.Now()
		if w := call(h.UpdateSettings, orgB, "admin-b", "PUT", "/settings",
			payload(20, true, true, "b.example.test")); w.Code != 200 {
			t.Fatalf("org B save: status %d, body %s", w.Code, w.Body.String())
		}
		time.Sleep(1100 * time.Millisecond) // NOW() has sub-second resolution; be sure the read is later
		w := call(h.GetSettings, orgB, "admin-b", "GET", "/settings", "")
		var got handlers.Settings
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if got.UpdatedAt.Before(before) || got.UpdatedAt.After(time.Now().Add(-time.Second)) {
			t.Errorf("updated_at is %v; want the save's timestamp, not the read's. "+
				"The field was seeded with time.Now() before the loop that keeps the "+
				"most recent row, so the comparison was unreachable and the endpoint "+
				"reported the settings as changed at the moment of every read",
				got.UpdatedAt)
		}
		if got.UpdatedBy != "admin-b" {
			t.Errorf("updated_by is %q, want admin-b", got.UpdatedBy)
		}
	})
}

// The continuous-auth engine, migration v157.
//
// A RISK ENGINE WHOSE ONLY INPUT TABLE HAD NO WRITER. auth_contexts was read at
// three sites in continuous_auth.go and written at none — not by a handler, not
// by the login path, not by a seed or a migration. So CalculateSessionRisk
// returned "no rows in result set" for every session that has ever existed and
// all three registered routes only ever returned 500; and UpdateAuthScore's
// UPDATE matched nothing and reported success.
//
// The engine now reads `sessions` and `session_risks`, which are written, carry
// org_id, and are behind the RLS belt. These cases prove it works at all, and
// that it works for one tenant at a time.
func TestContinuousAuth_ReadsRealSessions(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010"
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('ca-b','ca-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var userA string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		orgA, "ca-a-"+suffix, "ca-a-"+suffix+"@example.test").Scan(&userA); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	var sessionA string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, client_id, ip_address, user_agent, started_at, last_seen_at, expires_at, org_id, auth_methods)
		VALUES ($1::uuid, 'console', '203.0.113.10', 'Mozilla/5.0', NOW(), NOW(), NOW() + INTERVAL '1 hour', $2::uuid, ARRAY['password','totp'])
		RETURNING id::text`, userA, orgA).Scan(&sessionA); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	ctxA := orgctx.With(ctx, orgctx.Org{ID: orgA})
	ctxB := orgctx.With(ctx, orgctx.Org{ID: orgB})
	svc := &continuousAuthService{db: db, logger: zap.NewNop(), config: defaultContinuousAuthConfig()}

	t.Run("a session that exists is scored instead of 500ing", func(t *testing.T) {
		risk, err := svc.CalculateSessionRisk(ctxA, sessionA)
		if err != nil {
			t.Fatalf("scoring a real session failed: %v. Before v157 this read "+
				"auth_contexts, which nothing has ever written a row to, so every "+
				"call returned 'no rows in result set'", err)
		}
		if risk.RiskLevel == "" {
			t.Error("no risk level on the result")
		}
		// A fresh session with no adverse signal must not be graded critical.
		// The check and update routes used to build configs with zero
		// thresholds, and determineRiskLevel tests `>= CriticalRiskThreshold`
		// first, so every session on those routes graded critical -> terminate.
		if risk.RiskLevel == "critical" || risk.ActionRequired == "terminate" {
			t.Errorf("a fresh session graded %s/%s", risk.RiskLevel, risk.ActionRequired)
		}
		// The response says which factors it could actually measure.
		measured, ok := risk.Context["factors_measured"].(map[string]bool)
		if !ok {
			t.Fatalf("no factors_measured in the response context: %v", risk.Context)
		}
		if measured["device_anomaly"] {
			t.Error("device_anomaly reported as measured; sessions carries no fingerprint")
		}
		if !measured["velocity"] || !measured["session_age"] {
			t.Errorf("live factors reported as unmeasured: %v", measured)
		}
		if got := risk.Context["auth_strength"]; got != "high" {
			t.Errorf("auth_strength is %v, want high: the session's auth_methods "+
				"include totp, and v133 added that column for exactly this", got)
		}
	})

	t.Run("another tenant cannot score or terminate this session", func(t *testing.T) {
		if _, err := svc.CalculateSessionRisk(ctxB, sessionA); err == nil {
			t.Error("org B scored org A's session. RequireReauthentication turns a " +
				"critical score into 'terminate', so reading another tenant's session " +
				"here is the first half of ending it")
		}
		if err := svc.UpdateAuthScore(ctxB, sessionA, "failed_auth", nil); err == nil {
			t.Error("org B pushed a failed_auth event onto org A's session")
		}
	})

	t.Run("a risk event is recorded where the engine can read it back", func(t *testing.T) {
		// The score is cumulative: the subtest above already scored this
		// session and stored the result, so failed_auth's +20 lands on top of
		// whatever the factors made of it.
		before, err := svc.GetAuthContext(ctxA, sessionA)
		if err != nil {
			t.Fatalf("get auth context: %v", err)
		}

		if err := svc.UpdateAuthScore(ctxA, sessionA, "failed_auth",
			map[string]interface{}{"source": "test"}); err != nil {
			t.Fatalf("update auth score: %v", err)
		}
		var n int
		var risk, previous float64
		var recordedSource string
		if err := db.Pool.QueryRow(ctx, `
			SELECT COUNT(*), COALESCE(MAX(overall_risk), 0), COALESCE(MAX(previous_risk), 0),
			       COALESCE(MAX(risk_factors #>> '{metadata,source}'), '')
			FROM session_risks
			WHERE session_id = $1::uuid AND org_id = $2::uuid
			  AND risk_factors->>'event' = 'failed_auth'`,
			sessionA, orgA).Scan(&n, &risk, &previous, &recordedSource); err != nil {
			t.Fatalf("read back session_risks: %v", err)
		}
		if n != 1 {
			t.Fatalf("want 1 recorded failed_auth event, got %d. The old body UPDATEd "+
				"auth_contexts, matched no rows, and answered 'auth score updated'", n)
		}
		if want := before.CurrentRiskScore + 20; risk != want {
			t.Errorf("failed_auth scored %v, want %v (previous %v + 20)", risk, want, before.CurrentRiskScore)
		}
		if previous != before.CurrentRiskScore {
			t.Errorf("previous_risk recorded as %v, want %v", previous, before.CurrentRiskScore)
		}
		// The caller's metadata used to be dropped on the floor: the old body
		// marshalled the context's own map and ignored the argument.
		if recordedSource != "test" {
			t.Errorf("the event's metadata was not recorded (source=%q)", recordedSource)
		}
		// And the engine reads its own writing back as the current score.
		after, err := svc.GetAuthContext(ctxA, sessionA)
		if err != nil {
			t.Fatalf("get auth context: %v", err)
		}
		if after.CurrentRiskScore != risk {
			t.Errorf("current risk score is %v, want the %v just recorded", after.CurrentRiskScore, risk)
		}
	})

	t.Run("an unreportable event is refused, not scored as zero", func(t *testing.T) {
		err := svc.UpdateAuthScore(ctxA, sessionA, "definitely_not_an_event", nil)
		if err == nil {
			t.Fatal("an unknown event was accepted; the old switch fell through to " +
				"a zero adjustment and the handler answered 'auth score updated'")
		}
		if !errors.Is(err, errUnknownRiskEvent) {
			t.Errorf("want an unknown-event error, got %v", err)
		}
	})
}
