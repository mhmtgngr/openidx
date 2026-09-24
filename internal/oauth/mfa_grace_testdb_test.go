package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/migrations"
)

// mfaGraceFixture is the migrated schema, the real identity service, and one
// organization with one MFA policy, whose methods and grace period each test
// sets.
type mfaGraceFixture struct {
	t      *testing.T
	db     *database.PostgresDB
	s      *Service
	org    string
	orgCtx context.Context
	suffix string
	policy string
}

const mfaGracePassword = "a-long-enough-test-password"

func newMFAGraceFixture(t *testing.T) *mfaGraceFixture {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { rdb.Close() })

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	cfg := &config.Config{}                            // adaptive MFA off: risk never asks for the factor
	f := &mfaGraceFixture{
		t:  t,
		db: db,
		s: &Service{
			db:              db,
			redis:           &database.RedisClient{Client: rdb},
			config:          cfg,
			logger:          zap.NewNop(),
			identityService: identity.NewService(db, nil, cfg, zap.NewNop()),
		},
		org:    org,
		orgCtx: orgctx.With(ctx, orgctx.Org{ID: org}),
		suffix: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ($1, '', true, 10, '{}', '[]', 0, $2::uuid) RETURNING id::text`,
		"required-"+f.suffix, org).Scan(&f.policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return f
}

func (f *mfaGraceFixture) exec(sql string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", strings.Fields(sql)[0], err)
	}
}

// setPolicy writes the policy's methods and grace period as the admin API
// would, and, like the API on a method change, forgets the running windows.
func (f *mfaGraceFixture) setPolicy(methods string, graceHours int) {
	f.t.Helper()
	f.exec(`UPDATE mfa_policies SET required_methods = $1::jsonb, grace_period_hours = $2 WHERE id = $3::uuid`,
		methods, graceHours, f.policy)
	f.exec(`DELETE FROM mfa_policy_grace WHERE policy_id = $1::uuid`, f.policy)
}

// user creates a user with a password and the given factors: totp, email,
// bypass (an administrator's bypass code), or trusted:<fingerprint>.
func (f *mfaGraceFixture) user(name string, factors ...string) *identity.User {
	f.t.Helper()
	hash, err := pwhash.Hash(mfaGracePassword)
	if err != nil {
		f.t.Fatalf("hash password: %v", err)
	}
	u := &identity.User{UserName: name + "-" + f.suffix}
	if err := f.db.Pool.QueryRow(context.Background(), `
		INSERT INTO users (org_id, username, email, enabled, password_hash)
		VALUES ($1::uuid, $2, $3, true, $4) RETURNING id::text`,
		f.org, u.UserName, u.UserName+"@example.test", hash).Scan(&u.ID); err != nil {
		f.t.Fatalf("seed user %s: %v", name, err)
	}
	for _, factor := range factors {
		switch {
		case factor == "totp":
			f.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
				VALUES ($1::uuid, 'JBSWY3DPEHPK3PXP', true, NOW(), $2::uuid)`, u.ID, f.org)
		case factor == "email":
			f.exec(`INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id)
				VALUES ($1::uuid, $2, true, $3::uuid)`, u.ID, u.UserName+"@example.test", f.org)
		case factor == "bypass":
			f.exec(`INSERT INTO mfa_bypass_codes (user_id, code_hash, reason, generated_by, valid_until, org_id)
				VALUES ($1::uuid, 'not-a-real-hash', 'grace test', $1::uuid, NOW() + interval '1 day', $2::uuid)`, u.ID, f.org)
		case strings.HasPrefix(factor, "trusted:"):
			f.exec(`INSERT INTO trusted_browsers (user_id, browser_hash, name, ip_address, user_agent, expires_at, org_id)
				VALUES ($1::uuid, $2, 'test browser', '203.0.113.7', 'evidence-run', NOW() + interval '30 days', $3::uuid)`,
				u.ID, strings.TrimPrefix(factor, "trusted:"), f.org)
		default:
			f.t.Fatalf("unknown factor %q", factor)
		}
	}
	return u
}

// backdateGrace moves the start of u's window back, as if their first sign-in
// under the policy had been that long ago.
func (f *mfaGraceFixture) backdateGrace(u *identity.User, ago time.Duration) {
	f.t.Helper()
	tag, err := f.db.Pool.Exec(context.Background(), `
		UPDATE mfa_policy_grace SET started_at = NOW() - $1::interval
		 WHERE policy_id = $2::uuid AND user_id = $3::uuid`, ago.String(), f.policy, u.ID)
	if err != nil || tag.RowsAffected() != 1 {
		f.t.Fatalf("backdate %s's window: rows=%d err=%v (was it recorded?)", u.UserName, tag.RowsAffected(), err)
	}
}

func (f *mfaGraceFixture) windows(u *identity.User) int {
	f.t.Helper()
	var n int
	if err := f.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM mfa_policy_grace WHERE user_id = $1::uuid`, u.ID).Scan(&n); err != nil {
		f.t.Fatalf("count windows: %v", err)
	}
	return n
}

func (f *mfaGraceFixture) decide(u *identity.User, fingerprint string) mfaEvaluation {
	f.t.Helper()
	return f.s.evaluateMFA(f.orgCtx, u, "203.0.113.7", "evidence-run", fingerprint, "", false, 0, nil)
}

// A policy that requires methods, at the login decision (evaluateMFA), against
// the migrated schema and the real identity service. Each rule is shown from
// both sides: what the policy changes, and the same login without it.
func TestMFAPolicyRequiredMethodsAtTheLoginDecision(t *testing.T) {
	f := newMFAGraceFixture(t)

	t.Run("a user with a required method is offered only the required methods and their bypass code", func(t *testing.T) {
		u := f.user("has-totp", "totp", "email", "bypass")

		f.setPolicy(`[]`, 0)
		if ev := f.decide(u, ""); !ev.Challenge || !hasMethod(ev.Methods, "email") {
			t.Fatalf("with no method required, any enrolled factor is offered, email among them: %+v", ev)
		}

		f.setPolicy(`["totp"]`, 72)
		ev := f.decide(u, "")
		if !ev.Challenge || !ev.PolicyRequired {
			t.Fatalf("a user with the required method must be challenged: %+v", ev)
		}
		if want := []string{"totp", "bypass"}; !reflect.DeepEqual(ev.Methods, want) {
			t.Fatalf("offered %v, want %v: the policy requires TOTP, so email must not satisfy it", ev.Methods, want)
		}
		if ev.EnrollmentDue != nil || ev.EnrollmentRequired || f.windows(u) != 0 {
			t.Fatalf("a user who has the method has no window: %+v, %d rows", ev, f.windows(u))
		}
	})

	t.Run("a remembered browser does not stand in for a required method", func(t *testing.T) {
		u := f.user("remembered", "totp", "trusted:fp-remembered")

		f.setPolicy(`[]`, 0)
		if ev := f.decide(u, "fp-remembered"); ev.Challenge || !ev.SkipMFA {
			t.Fatalf("with no method required, a remembered browser skips the factor: %+v", ev)
		}

		f.setPolicy(`["totp"]`, 72)
		if ev := f.decide(u, "fp-remembered"); !ev.Challenge || ev.SkipMFA {
			t.Fatalf("the product does not record which factor a browser was remembered with, so a policy that requires one must challenge: %+v", ev)
		}
	})

	t.Run("inside the grace period a user without the method signs in as before, and is told by when", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 72)
		u := f.user("email-only", "email")

		first := f.decide(u, "")
		if !first.GraceBegan || first.EnrollmentDue == nil || first.EnrollmentRequired {
			t.Fatalf("the first sign-in under the policy must start the window and say so: %+v", first)
		}
		if !first.Challenge || !hasMethod(first.Methods, "email") {
			t.Fatalf("inside the window the user signs in as before, with the factor they have: %+v", first)
		}
		if due := first.EnrollmentDue; !reflect.DeepEqual(due.Methods, []string{"totp"}) || due.Overdue ||
			due.Deadline.Before(time.Now().Add(71*time.Hour)) || due.Deadline.After(time.Now().Add(73*time.Hour)) {
			t.Fatalf("notice %+v, want TOTP due in 72 hours", due)
		}

		second := f.decide(u, "")
		if second.GraceBegan || second.EnrollmentDue == nil || !second.EnrollmentDue.Deadline.Equal(first.EnrollmentDue.Deadline) {
			t.Fatalf("a later sign-in must keep the first window, not start another: first %+v, second %+v", first.EnrollmentDue, second)
		}
	})

	t.Run("a user with no factor at all is not challenged inside the grace period", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 72)
		u := f.user("no-factor")
		ev := f.decide(u, "")
		if ev.Challenge || ev.EnrollmentRequired || ev.EnrollmentDue == nil {
			t.Fatalf("inside the window a user with nothing to challenge signs in, and is told: %+v", ev)
		}
	})

	t.Run("after the grace period a user without the method or a bypass code is refused", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 72)
		u := f.user("overdue", "email")
		f.decide(u, "")
		f.backdateGrace(u, 73*time.Hour)

		ev := f.decide(u, "")
		if !ev.EnrollmentRequired || ev.Challenge {
			t.Fatalf("73 hours into a 72-hour window the login must be refused: %+v", ev)
		}

		// The other side: the same window under a longer grace period is open
		// again. The deadline is computed at sign-in, so raising the period
		// extends every window already running.
		f.exec(`UPDATE mfa_policies SET grace_period_hours = 96 WHERE id = $1::uuid`, f.policy)
		ev = f.decide(u, "")
		if ev.EnrollmentRequired || ev.EnrollmentDue == nil || !ev.Challenge {
			t.Fatalf("after the grace period was raised to 96 hours the window is open again: %+v", ev)
		}
		if left := time.Until(ev.EnrollmentDue.Deadline); left < 22*time.Hour || left > 24*time.Hour {
			t.Fatalf("%v left, want about 23 hours: the window must keep its start", left)
		}
	})

	t.Run("after the grace period a bypass code is the only way in", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 72)
		u := f.user("overdue-bypass", "email", "bypass")
		f.decide(u, "")
		f.backdateGrace(u, 73*time.Hour)

		ev := f.decide(u, "")
		if !ev.Challenge || ev.EnrollmentRequired || !reflect.DeepEqual(ev.Methods, []string{"bypass"}) {
			t.Fatalf("after the window a bypass code, and only it, must be offered: %+v", ev)
		}
		if ev.EnrollmentDue == nil || !ev.EnrollmentDue.Overdue {
			t.Fatalf("the user must be told the time has passed: %+v", ev.EnrollmentDue)
		}
	})

	t.Run("a policy with no grace period refuses at the first sign-in", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 0)
		u := f.user("no-grace", "email")
		ev := f.decide(u, "")
		if !ev.EnrollmentRequired || ev.Challenge || ev.GraceBegan {
			t.Fatalf("with no grace period there is no window to start: %+v", ev)
		}
	})

	t.Run("the policy the console lists first decides", func(t *testing.T) {
		f.setPolicy(`["totp"]`, 0)
		u := f.user("ordered", "email")
		var other string
		if err := f.db.Pool.QueryRow(context.Background(), `
			INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
			VALUES ($1, '', true, 20, '{}', '[]', 0, $2::uuid) RETURNING id::text`,
			"any-factor-"+f.suffix, f.org).Scan(&other); err != nil {
			t.Fatalf("seed a second policy: %v", err)
		}
		t.Cleanup(func() { f.exec(`DELETE FROM mfa_policies WHERE id = $1::uuid`, other) })

		if ev := f.decide(u, ""); !ev.EnrollmentRequired {
			t.Fatalf("priority 10 is listed before 20, so its TOTP requirement decides: %+v", ev)
		}
		f.exec(`UPDATE mfa_policies SET priority = 1 WHERE id = $1::uuid`, other)
		if ev := f.decide(u, ""); ev.EnrollmentRequired || !ev.Challenge {
			t.Fatalf("priority 1 is now listed first, so any factor satisfies it: %+v", ev)
		}
	})
}

// The same rules at POST /oauth/login: what the sign-in page receives, and the
// audit trail the refusals leave.
func TestMFAPolicyGraceAtTheLoginEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newMFAGraceFixture(t)
	f.setPolicy(`["totp"]`, 72)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	})
	router.POST("/oauth/login", f.s.handleLogin)

	login := func(u *identity.User) (int, map[string]interface{}) {
		t.Helper()
		ls := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"client_id": "grace-client", "redirect_uri": "https://app.example.test/callback",
			"scope": "openid", "state": "st-1",
		})
		if err := f.s.redis.Client.Set(context.Background(), "login_session:"+ls, params, time.Minute).Err(); err != nil {
			t.Fatalf("seed login session: %v", err)
		}
		body, _ := json.Marshal(map[string]string{"username": u.UserName, "password": mfaGracePassword, "login_session": ls})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("login response is not JSON: %d %s", w.Code, w.Body.String())
		}
		return w.Code, resp
	}
	audited := func(u *identity.User, action string) bool {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var n int
			if err := f.db.Pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM audit_events WHERE action = $1 AND actor_id = $2`, action, u.ID).Scan(&n); err == nil && n > 0 {
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		return false
	}

	t.Run("a user with the method is challenged with it alone", func(t *testing.T) {
		code, resp := login(f.user("endpoint-totp", "totp", "email"))
		if code != http.StatusOK || resp["mfa_required"] != true {
			t.Fatalf("want an MFA challenge, got %d %v", code, resp)
		}
		if methods := fmt.Sprint(resp["mfa_methods"]); methods != "[totp]" {
			t.Fatalf("offered %s, want [totp]", methods)
		}
		if _, ok := resp["mfa_enrollment_due"]; ok {
			t.Fatalf("a user who has the method is told nothing: %v", resp)
		}
	})

	u := f.user("endpoint-email", "email")
	t.Run("inside the grace period the challenge carries the notice", func(t *testing.T) {
		code, resp := login(u)
		if code != http.StatusOK || resp["mfa_required"] != true {
			t.Fatalf("want an MFA challenge with the factor the user has, got %d %v", code, resp)
		}
		due, ok := resp["mfa_enrollment_due"].(map[string]interface{})
		if !ok || fmt.Sprint(due["methods"]) != "[totp]" || due["deadline"] == nil || due["overdue"] != nil {
			t.Fatalf("notice %v, want TOTP and a deadline", resp["mfa_enrollment_due"])
		}
		if !audited(u, "mfa_grace_started") {
			t.Fatal("the start of the grace period was not audited")
		}
	})
	t.Run("after the grace period the login is refused and says why", func(t *testing.T) {
		f.backdateGrace(u, 73*time.Hour)
		code, resp := login(u)
		if code != http.StatusForbidden || resp["error"] != "mfa_enrollment_required" {
			t.Fatalf("want 403 mfa_enrollment_required, got %d %v", code, resp)
		}
		if methods := fmt.Sprint(resp["required_methods"]); methods != "[totp]" {
			t.Fatalf("required_methods %s, want [totp]", methods)
		}
		if desc, _ := resp["error_description"].(string); !strings.Contains(desc, "totp") || !strings.Contains(desc, "bypass code") {
			t.Fatalf("the description must name the method and the way back in: %q", desc)
		}
		if !audited(u, "mfa_enrollment_required") {
			t.Fatal("the refusal was not audited")
		}
	})
}

// The notice reaches the response that completes the login, whichever step
// that is: issueAuthorizationCode reads it from the OAuth parameters that
// carried it from the password step.
func TestAuthorizationCodeResponseCarriesTheEnrollmentNotice(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _ := ssoSetupDB(t)
	issue := func(params map[string]string) map[string]interface{} {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/oauth/login", nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
		base := map[string]string{"client_id": "c", "redirect_uri": ssoTestRedirect, "scope": "openid", "state": "st-1"}
		for k, v := range params {
			base[k] = v
		}
		svc.issueAuthorizationCode(c, base, "11111111-1111-1111-1111-111111111111")
		if w.Code != http.StatusOK {
			t.Fatalf("issue: %d %s", w.Code, w.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	if resp := issue(nil); resp["mfa_enrollment_due"] != nil {
		t.Fatalf("no notice was carried, yet the response has one: %v", resp)
	}
	due := `{"methods":["webauthn"],"deadline":"2026-10-01T00:00:00Z"}`
	resp := issue(map[string]string{paramMFAEnrollmentDue: due})
	var want interface{}
	_ = json.Unmarshal([]byte(due), &want)
	if !reflect.DeepEqual(resp["mfa_enrollment_due"], want) {
		t.Fatalf("notice %v, want %s", resp["mfa_enrollment_due"], due)
	}
	if resp["redirect_url"] == nil {
		t.Fatalf("the notice must ride alongside the redirect, not replace it: %v", resp)
	}
	if resp := issue(map[string]string{paramMFAEnrollmentDue: "not json"}); resp["mfa_enrollment_due"] != nil {
		t.Fatalf("a notice that is not JSON must be dropped, not echoed: %v", resp)
	}
}
