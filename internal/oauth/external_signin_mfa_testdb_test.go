package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/identity"
)

// A SIGN-IN THROUGH AN EXTERNAL IDENTITY ASKS THE PASSWORD LOGIN'S QUESTION.
//
// GET /oauth/social/callback (a social provider) and GET /oauth/callback (an
// enterprise identity provider, the console's SSO buttons) issued a code, or
// tokens, to whoever the provider vouched for, second factor or not. They now
// ask evaluateMFA: a user with a factor goes on to the login page's
// second-factor step with an MFA session, which /oauth/mfa-verify completes; a
// user whose grace period is over, or a sign-in the risk engine denies, is sent
// back with the reason; a user who needs nothing more signs in as before.
//
// Driven through RegisterRoutes as cmd/oauth-service wires it, over a migrated
// database, with the real identity service and a provider served by httptest.

// fakeProvider is an OIDC provider at the paths the product derives from an
// issuer URL: it answers the token and userinfo requests for the account a
// test names, and signs an ID token for the enterprise flow.
type fakeProvider struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	user map[string]map[string]string // code -> claims
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeProvider{key: key, user: map[string]map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		p.mu.Lock()
		claims, ok := p.user[code]
		p.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": claims["sub"], "email": claims["email"], "name": "Fed User",
			"iss": p.srv.URL, "aud": "fed-client", "exp": time.Now().Add(time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		idToken, _ := tok.SignedString(p.key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-" + code, "token_type": "Bearer", "expires_in": 60, "id_token": idToken,
		})
	})
	mux.HandleFunc("/protocol/openid-connect/userinfo", func(w http.ResponseWriter, r *http.Request) {
		code := strings.TrimPrefix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "at-")
		p.mu.Lock()
		claims, ok := p.user[code]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "unknown token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": claims["sub"], "email": claims["email"], "name": "Fed User"})
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// code makes the provider answer the next exchange of the returned code for
// the account sub, email.
func (p *fakeProvider) code(sub, email string) string {
	c := GenerateRandomToken(12)
	p.mu.Lock()
	p.user[c] = map[string]string{"sub": sub, "email": email}
	p.mu.Unlock()
	return c
}

type externalHarness struct {
	*tokenHarness
	api      *gin.Engine
	provider *fakeProvider
	idp      string
}

func newExternalHarness(t *testing.T) *externalHarness {
	h := newTokenHarness(t)
	idSvc := identity.NewService(h.db, h.issuer.redis, &config.Config{
		Environment: "production", OAuthIssuer: h.issuer.issuer, OAuthJWKSURL: h.jwksURL,
	}, zap.NewNop())
	h.issuer.identityService = idSvc
	h.issuer.idpCipher = secretcrypt.NewNoop()
	p := newFakeProvider(t)
	idp := h.scalar(`INSERT INTO identity_providers (name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, org_id)
		VALUES ('Fed', 'oidc', $1, 'fed-client', 'fed-secret', '["openid","email"]', true, $2::uuid) RETURNING id::text`,
		p.srv.URL, middleware.DefaultOrgID)
	return &externalHarness{tokenHarness: h, api: h.oauthRouteTable(nil), provider: p, idp: idp}
}

func (x *externalHarness) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	x.api.ServeHTTP(w, req)
	return w
}

func (x *externalHarness) post(path, bearer string, body interface{}) (int, map[string]interface{}) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	x.api.ServeHTTP(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// loginSession starts a pending sign-in to the console, as /oauth/authorize does.
func (x *externalHarness) loginSession() string {
	x.t.Helper()
	id := GenerateRandomToken(32)
	params, _ := json.Marshal(map[string]string{
		"client_id": "admin-console", "redirect_uri": "http://localhost:3000/login",
		"response_type": "code", "scope": "openid", "state": "st-1",
	})
	if err := x.issuer.redis.Client.Set(context.Background(), "login_session:"+id, params, 10*time.Minute).Err(); err != nil {
		x.t.Fatalf("seed login session: %v", err)
	}
	return id
}

// linkedUser creates a user signed in to through the provider as sub, with
// the given factors: "totp" or "password".
func (x *externalHarness) linkedUser(name string, factors ...string) (userID, sub, totpSecret string) {
	x.t.Helper()
	userID = x.seedUser(middleware.DefaultOrgID, name)
	sub = "sub-" + name + "-" + x.suffix
	email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, userID)
	x.exec(`INSERT INTO social_account_links (user_id, provider_id, external_id, email, org_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid)`, userID, x.idp, sub, email, middleware.DefaultOrgID)
	x.exec(`INSERT INTO user_identity_links (user_id, provider_id, external_id, external_email, org_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid)`, userID, x.idp, sub, email, middleware.DefaultOrgID)
	for _, f := range factors {
		switch f {
		case "totp":
			key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: name})
			if err != nil {
				x.t.Fatalf("generate TOTP key: %v", err)
			}
			totpSecret = key.Secret()
			x.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
				VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, userID, totpSecret, middleware.DefaultOrgID)
		case "password":
			x.exec(`UPDATE users SET password_hash = $1 WHERE id = $2::uuid`, x.passwordHash(), userID)
		}
	}
	return userID, sub, totpSecret
}

const externalPassword = "an-external-users-password"

func (x *externalHarness) passwordHash() string {
	x.t.Helper()
	hash, err := pwhash.Hash(externalPassword)
	if err != nil {
		x.t.Fatalf("hash: %v", err)
	}
	return hash
}

// socialSignIn runs GET /oauth/social/:id and the provider's callback for sub.
func (x *externalHarness) socialSignIn(sub, email, loginSession string) *httptest.ResponseRecorder {
	x.t.Helper()
	path := "/oauth/social/" + x.idp
	if loginSession != "" {
		path += "?login_session=" + url.QueryEscape(loginSession)
	}
	w := x.get(path)
	if w.Code != http.StatusFound {
		x.t.Fatalf("social start: %d %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	state := loc.Query().Get("state")
	return x.get("/oauth/social/callback?" + url.Values{"code": {x.provider.code(sub, email)}, "state": {state}}.Encode())
}

func (x *externalHarness) codes(userID string) int {
	x.t.Helper()
	var n int
	if err := x.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM oauth_authorization_codes WHERE user_id = $1::uuid`, userID).Scan(&n); err != nil {
		x.t.Fatalf("count codes: %v", err)
	}
	return n
}

// handedToSecondFactor asserts a redirect to the login page's second-factor
// step and returns its MFA session.
func handedToSecondFactor(t *testing.T, w *httptest.ResponseRecorder, methods string) string {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect to the second-factor step, got %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Path != "/login" || loc.Query().Get("mfa_session") == "" {
		t.Fatalf("want /login?mfa_session=..., got %q", w.Header().Get("Location"))
	}
	if got := loc.Query().Get("mfa_methods"); got != methods {
		t.Fatalf("mfa_methods = %q, want %q", got, methods)
	}
	return loc.Query().Get("mfa_session")
}

func TestASocialSignInAsksForTheSecondFactor(t *testing.T) {
	x := newExternalHarness(t)

	t.Run("a user with no second factor signs in with the provider", func(t *testing.T) {
		user, sub, _ := x.linkedUser("social-plain")
		email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
		w := x.socialSignIn(sub, email, x.loginSession())
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusOK || !strings.Contains(out["redirect_url"].(string), "code=") {
			t.Fatalf("want a code, got %d %s", w.Code, w.Body.String())
		}
		if n := x.codes(user); n != 1 {
			t.Fatalf("%d codes, want 1", n)
		}
	})

	t.Run("a user with TOTP goes on to it, and the code is issued after it", func(t *testing.T) {
		user, sub, secret := x.linkedUser("social-totp", "totp")
		email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
		mfaSession := handedToSecondFactor(t, x.socialSignIn(sub, email, x.loginSession()), "totp")
		if n := x.codes(user); n != 0 {
			t.Fatalf("%d codes issued before the second factor, want 0", n)
		}
		status, _ := x.post("/oauth/mfa-verify", "", map[string]string{"mfa_session": mfaSession, "code": "000000", "method": "totp"})
		if status != http.StatusUnauthorized || x.codes(user) != 0 {
			t.Fatalf("a wrong code: status %d, codes %d; want 401 and none", status, x.codes(user))
		}
		code, _ := totp.GenerateCode(secret, time.Now())
		status, out := x.post("/oauth/mfa-verify", "", map[string]string{"mfa_session": mfaSession, "code": code, "method": "totp"})
		if status != http.StatusOK || !strings.HasPrefix(out["redirect_url"].(string), "http://localhost:3000/login?code=") {
			t.Fatalf("the second factor: status %d (%v), want a code for the pending request", status, out)
		}
		if n := x.codes(user); n != 1 {
			t.Fatalf("%d codes, want 1", n)
		}
	})

	t.Run("without a pending request, tokens only for who needs nothing more", func(t *testing.T) {
		user, sub, _ := x.linkedUser("social-direct-totp", "totp")
		email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
		w := x.socialSignIn(sub, email, "")
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "access_token") {
			t.Fatalf("a user with TOTP and no pending request: %d %s, want 403 and no tokens", w.Code, w.Body.String())
		}
		plain, psub, _ := x.linkedUser("social-direct-plain")
		pemail := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, plain)
		w = x.socialSignIn(psub, pemail, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access_token") {
			t.Fatalf("a user with no factor: %d %s, want tokens", w.Code, w.Body.String())
		}
	})
}

// An MFA policy whose grace period is over refuses the external sign-in, and a
// policy that names methods offers only those.
func TestASocialSignInFollowsTheMFAPolicy(t *testing.T) {
	x := newExternalHarness(t)
	x.exec(`INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ('require-totp', '', true, 10, '{}', '["totp"]', 0, $1::uuid)`, middleware.DefaultOrgID)

	user, sub, _ := x.linkedUser("policy-none")
	email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)
	ls := x.loginSession()
	w := x.socialSignIn(sub, email, ls)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc.Path != "/login" || loc.Query().Get("error") != "sso_mfa_enrollment_required" ||
		loc.Query().Get("login_session") != ls {
		t.Fatalf("a user without the required method after the grace period: %d %q", w.Code, w.Header().Get("Location"))
	}
	if n := x.codes(user); n != 0 {
		t.Fatalf("%d codes, want 0", n)
	}

	withTOTP, tsub, _ := x.linkedUser("policy-totp", "totp")
	temail := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, withTOTP)
	handedToSecondFactor(t, x.socialSignIn(tsub, temail, x.loginSession()), "totp")
}

// The console's SSO buttons: /oauth/authorize?idp_hint= to the provider and back
// to GET /oauth/callback.
func TestAnEnterpriseSSOSignInAsksForTheSecondFactor(t *testing.T) {
	x := newExternalHarness(t)
	ssoSignIn := func(sub, email string) *httptest.ResponseRecorder {
		t.Helper()
		q := url.Values{
			"response_type": {"code"}, "client_id": {"admin-console"},
			"redirect_uri": {"http://localhost:3000/login"}, "scope": {"openid"}, "state": {"st-2"},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
			"idp_hint": {x.idp},
		}
		w := x.get("/oauth/authorize?" + q.Encode())
		if w.Code != http.StatusFound {
			t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		return x.get("/oauth/callback?" + url.Values{"code": {x.provider.code(sub, email)}, "state": {loc.Query().Get("state")}}.Encode())
	}
	seed := func(name string, factors ...string) (string, string, string) {
		user := x.seedUser(middleware.DefaultOrgID, name)
		sub := "sso-" + name + "-" + x.suffix
		x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, sub, user)
		secret := ""
		for _, f := range factors {
			if f == "totp" {
				key, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: name})
				secret = key.Secret()
				x.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
					VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, user, secret, middleware.DefaultOrgID)
			}
		}
		return user, sub, secret
	}

	plain, psub, _ := seed("sso-plain")
	w := ssoSignIn(psub, x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, plain))
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("a user with no factor: %d %q, want a code", w.Code, w.Header().Get("Location"))
	}
	if ch := x.scalar(`SELECT COALESCE(code_challenge, '') FROM oauth_authorization_codes WHERE user_id = $1::uuid`, plain); ch == "" {
		t.Fatal("the SSO code carries no PKCE challenge: a public client cannot redeem it")
	}

	user, sub, secret := seed("sso-totp", "totp")
	mfaSession := handedToSecondFactor(t, ssoSignIn(sub, x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, user)), "totp")
	if n := x.codes(user); n != 0 {
		t.Fatalf("%d codes issued before the second factor, want 0", n)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	status, out := x.post("/oauth/mfa-verify", "", map[string]string{"mfa_session": mfaSession, "code": code, "method": "totp"})
	if status != http.StatusOK || out["redirect_url"] == nil {
		t.Fatalf("the second factor: status %d (%v), want a code", status, out)
	}
	if ch := x.scalar(`SELECT COALESCE(code_challenge, '') FROM oauth_authorization_codes WHERE user_id = $1::uuid`, user); ch == "" {
		t.Fatal("the code issued after the second factor carries no PKCE challenge")
	}
}
