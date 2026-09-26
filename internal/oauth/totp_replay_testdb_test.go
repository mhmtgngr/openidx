package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/identity"
)

// THE SIGN-IN AND STEP-UP ACCEPT A TOTP CODE ONCE.
//
// Both reach identity.VerifyTOTP: the password sign-in's second step
// (POST /oauth/login, then POST /oauth/mfa-verify) and mid-session step-up
// (POST /oauth/stepup-challenge, then POST /oauth/stepup-verify), which is what
// the step-up gate in front of a PAM launch and an admin write asks for. The
// verifier records the step each code belongs to on the credential, so a code
// spent on one path is spent on the other too.
//
// Driven through RegisterRoutes as cmd/oauth-service wires it: the tenant
// resolver in front and AuthWithAPIKey over the issuer's JWKS as the flow
// middleware, over a migrated database, with the real identity service.
func TestTheSignInAndStepUpAcceptATOTPCodeOnce(t *testing.T) {
	h := newTokenHarness(t)
	h.issuer.identityService = identity.NewService(h.db, h.issuer.redis, &config.Config{
		Environment: "production", OAuthIssuer: h.issuer.issuer, OAuthJWKSURL: h.jwksURL,
	}, zap.NewNop())
	api := h.oauthRouteTable(nil)
	ctx := context.Background()

	const password = "a-long-enough-test-password"
	hash, err := pwhash.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := h.seedUser(middleware.DefaultOrgID, "totp-once")
	username := h.scalar(`SELECT username FROM users WHERE id = $1::uuid`, user)
	h.exec(`UPDATE users SET password_hash = $1 WHERE id = $2::uuid`, hash, user)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: username})
	if err != nil {
		t.Fatalf("generate TOTP key: %v", err)
	}
	h.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
		VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, user, key.Secret(), middleware.DefaultOrgID)
	code := func(at time.Time) string {
		c, err := totp.GenerateCode(key.Secret(), at.UTC())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		return c
	}

	post := func(path, bearer string, body interface{}) (int, map[string]interface{}) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// signIn starts a sign-in to the console with the password and completes
	// its second step with a TOTP code.
	signIn := func(totpCode string) (int, map[string]interface{}) {
		t.Helper()
		loginSession := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"client_id": "admin-console", "redirect_uri": "http://localhost:3000/callback",
			"response_type": "code", "scope": "openid", "state": "st-1",
		})
		if err := h.issuer.redis.Client.Set(ctx, "login_session:"+loginSession, params, time.Minute).Err(); err != nil {
			t.Fatalf("seed login session: %v", err)
		}
		status, body := post("/oauth/login", "", map[string]string{
			"username": username, "password": password, "login_session": loginSession,
		})
		if status != http.StatusOK || body["mfa_required"] != true {
			t.Fatalf("password step: status %d (%v), want 200 with mfa_required", status, body)
		}
		mfaSession, _ := body["mfa_session"].(string)
		return post("/oauth/mfa-verify", "", map[string]string{
			"mfa_session": mfaSession, "code": totpCode, "method": "totp",
		})
	}

	now := time.Now()
	first := code(now)
	if status, body := signIn(first); status != http.StatusOK {
		t.Fatalf("the first sign-in with a fresh code: status %d (%v), want 200", status, body)
	}
	if status, body := signIn(first); status != http.StatusUnauthorized || body["error"] != "invalid_mfa_code" {
		t.Fatalf("the same code at a second sign-in: status %d (%v), want 401 invalid_mfa_code", status, body)
	}

	// Step-up on the session the first sign-in opened.
	var sessionID string
	if err := h.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`SELECT id::text FROM sessions WHERE user_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, user).Scan(&sessionID); err != nil {
		t.Fatalf("read the sign-in's session: %v", err)
	}
	bearer, err := h.issuer.GenerateJWT(orgctx.With(ctx, defaultOrg), user, "admin-console", "openid", 300, sessionID)
	if err != nil {
		t.Fatalf("mint the session's access token: %v", err)
	}
	status, body := post("/oauth/stepup-challenge", bearer, map[string]string{"reason": "pam_launch"})
	if status != http.StatusOK {
		t.Fatalf("step-up challenge: status %d (%v), want 200", status, body)
	}
	challenge, _ := body["challenge_id"].(string)
	stepUp := func(totpCode string) (int, map[string]interface{}) {
		t.Helper()
		return post("/oauth/stepup-verify", bearer, map[string]string{
			"challenge_id": challenge, "method": "totp", "code": totpCode,
		})
	}

	if status, body := stepUp(first); status != http.StatusUnauthorized {
		t.Fatalf("step-up with the code the sign-in spent: status %d (%v), want 401", status, body)
	}
	next := code(now.Add(30 * time.Second))
	if status, body := stepUp(next); status != http.StatusOK {
		t.Fatalf("step-up with the next step's code: status %d (%v), want 200", status, body)
	}
	if status, body := signIn(next); status != http.StatusUnauthorized {
		t.Fatalf("a sign-in with the code step-up spent: status %d (%v), want 401", status, body)
	}
}
