package oauth

// What was measured, before any of this existed: a token whose granted scope
// was the bare `openid` came back carrying `email` and `name`, and
// `GET /oauth/userinfo` presented with that same token answered with `email`,
// `name`, `given_name`, `family_name` and `preferred_username`. The consent
// screen showed the scope, the token carried it in its own `scope` claim, and
// nothing read it.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// scopeFixture is a service with a signing key and one user whose identity is
// worth protecting.
type scopeFixture struct {
	svc   *Service
	ctx   context.Context
	user  string
	email string
}

func setupScopeClaims(t *testing.T, emailVerified bool) *scopeFixture {
	t.Helper()
	svc, db := ssoSetupDB(t)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, org_id UUID NOT NULL, email TEXT,
			first_name TEXT, last_name TEXT, email_verified BOOLEAN DEFAULT false)`,
		`CREATE TABLE IF NOT EXISTS roles (id UUID PRIMARY KEY, name TEXT, org_id UUID)`,
		`CREATE TABLE IF NOT EXISTS user_roles (user_id UUID, role_id UUID, org_id UUID, expires_at TIMESTAMPTZ)`,
		`CREATE TABLE IF NOT EXISTS groups (id UUID PRIMARY KEY, name TEXT, org_id UUID)`,
		`CREATE TABLE IF NOT EXISTS permissions (id UUID PRIMARY KEY, resource TEXT, action TEXT)`,
	} {
		if _, err := db.Pool.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("schema: %v\n%s", err, stmt)
		}
	}
	if svc.privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		svc.privateKey = key
		svc.publicKey = &key.PublicKey
	}
	f := &scopeFixture{svc: svc, ctx: ctx, user: uuid.New().String(), email: "ada@example.test"}
	if _, err := db.Pool.Exec(context.Background(),
		`INSERT INTO users (id, org_id, email, first_name, last_name, email_verified)
		 VALUES ($1,$2,$3,'Ada','Lovelace',$4)`,
		f.user, ssoTestOrg, f.email, emailVerified); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return f
}

func (f *scopeFixture) accessToken(t *testing.T, scope string) (string, jwt.MapClaims) {
	t.Helper()
	tok, err := f.svc.GenerateJWT(f.ctx, f.user, "sso-client", scope, 3600)
	if err != nil {
		t.Fatalf("GenerateJWT(%q): %v", scope, err)
	}
	return tok, unverifiedClaims(t, tok)
}

func (f *scopeFixture) idToken(t *testing.T, scope string) jwt.MapClaims {
	t.Helper()
	tok, err := f.svc.GenerateIDToken(f.ctx, f.user, "sso-client", "", scope, 3600)
	if err != nil {
		t.Fatalf("GenerateIDToken(%q): %v", scope, err)
	}
	return unverifiedClaims(t, tok)
}

func unverifiedClaims(t *testing.T, tok string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

// userInfo calls the real endpoint with a real access token minted for scope.
func (f *scopeFixture) userInfo(t *testing.T, scope string) map[string]interface{} {
	t.Helper()
	tok, _ := f.accessToken(t, scope)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil).WithContext(f.ctx)
	c.Request.Header.Set("Authorization", "Bearer "+tok)
	f.svc.handleUserInfo(c)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo(%q): %d %s", scope, w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func mustAbsent(t *testing.T, where string, got map[string]interface{}, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := got[k]; ok {
			t.Fatalf("%s: %q must not be present, got %v", where, k, v)
		}
	}
}

func mustEqual(t *testing.T, where string, got map[string]interface{}, k string, want interface{}) {
	t.Helper()
	v, ok := got[k]
	if !ok {
		t.Fatalf("%s: %q missing", where, k)
	}
	if v != want {
		t.Fatalf("%s: %q = %v, want %v", where, k, v, want)
	}
}

// The bare `openid` scope buys authentication, not the end user's identity.
func TestBareOpenidGrantsNoIdentityClaims(t *testing.T) {
	f := setupScopeClaims(t, true)
	identity := []string{"email", "email_verified", "name", "given_name", "family_name", "preferred_username"}

	_, access := f.accessToken(t, "openid")
	mustAbsent(t, "access token", access, identity...)

	mustAbsent(t, "id token", f.idToken(t, "openid"), identity...)

	info := f.userInfo(t, "openid")
	mustAbsent(t, "userinfo", info, identity...)
	if _, ok := info["sub"]; !ok {
		t.Fatal("userinfo must still carry sub: OIDC Core §5.3.2 requires it and it is not a profile claim")
	}
}

// `profile` buys the name claims and nothing about the address.
func TestProfileScopeGrantsTheNameClaimsOnly(t *testing.T) {
	f := setupScopeClaims(t, true)
	for _, tc := range []struct {
		where string
		got   map[string]interface{}
	}{
		{"access token", func() map[string]interface{} { _, c := f.accessToken(t, "openid profile"); return c }()},
		{"id token", f.idToken(t, "openid profile")},
		{"userinfo", f.userInfo(t, "openid profile")},
	} {
		mustEqual(t, tc.where, tc.got, "name", "Ada Lovelace")
		mustEqual(t, tc.where, tc.got, "given_name", "Ada")
		mustEqual(t, tc.where, tc.got, "family_name", "Lovelace")
		mustEqual(t, tc.where, tc.got, "preferred_username", "ada@example.test")
		mustAbsent(t, tc.where, tc.got, "email", "email_verified")
	}
}

// `email` buys the address and nothing about the name.
func TestEmailScopeGrantsTheAddressOnly(t *testing.T) {
	f := setupScopeClaims(t, true)
	for _, tc := range []struct {
		where string
		got   map[string]interface{}
	}{
		{"access token", func() map[string]interface{} { _, c := f.accessToken(t, "openid email"); return c }()},
		{"id token", f.idToken(t, "openid email")},
		{"userinfo", f.userInfo(t, "openid email")},
	} {
		mustEqual(t, tc.where, tc.got, "email", "ada@example.test")
		mustEqual(t, tc.where, tc.got, "email_verified", true)
		mustAbsent(t, tc.where, tc.got, "name", "given_name", "family_name", "preferred_username")
	}
}

// An empty scope is read as "no scope in particular" when deciding whether a
// request is permitted, and as "nothing granted" here. Reading it as "every
// scope" would leave a client that omits scope better off than one that asks.
func TestAnEmptyScopeGrantsNoIdentityClaims(t *testing.T) {
	f := setupScopeClaims(t, true)
	identity := []string{"email", "email_verified", "name", "given_name", "family_name", "preferred_username"}
	_, access := f.accessToken(t, "")
	mustAbsent(t, "access token", access, identity...)
	mustAbsent(t, "id token", f.idToken(t, ""), identity...)
	mustAbsent(t, "userinfo", f.userInfo(t, ""), identity...)
}

// email_verified is read from the row, not asserted. A relying party uses this
// claim to decide whether it may match this identity onto an existing local
// account by address, so a hard-coded true is an account-takeover primitive.
func TestEmailVerifiedIsReadNotAssumed(t *testing.T) {
	f := setupScopeClaims(t, false)
	_, access := f.accessToken(t, "openid email")
	mustEqual(t, "access token", access, "email_verified", false)
	mustEqual(t, "id token", f.idToken(t, "openid email"), "email_verified", false)
	mustEqual(t, "userinfo", f.userInfo(t, "openid email"), "email_verified", false)
}

// The recorded decision from scope_claims.go, pinned: roles, groups and
// permissions are authorization facts the resource servers read, not identity
// claims about the end user, and gating them on `profile` would silently turn
// authorization off for a client that asked for `openid` alone. If that
// decision is ever revisited, this test is the thing that has to change with
// it rather than the behaviour drifting unnoticed.
func TestAuthorizationClaimsAreNotGatedOnAProfileScope(t *testing.T) {
	f := setupScopeClaims(t, true)
	_, access := f.accessToken(t, "openid")
	for _, k := range []string{"roles", "groups", "permissions"} {
		if _, ok := access[k]; !ok {
			t.Fatalf("access token lost %q under the bare openid scope", k)
		}
	}
	id := f.idToken(t, "openid")
	for _, k := range []string{"roles", "groups", "permissions"} {
		if _, ok := id[k]; !ok {
			t.Fatalf("id token lost %q under the bare openid scope", k)
		}
	}
}

// A CENSUS. Every claim this issuer can put in a token has to appear in the
// discovery document's claims_supported, because that list is what a relying
// party reads to decide what it may ask for. preferred_username, roles, groups
// and permissions were all emitted and none was listed.
//
// The register below is the exception list, and each entry carries its reason.
// A new claim added to a token and not to claims_supported fails here.
func TestDiscoveryAdvertisesEveryClaimTheIssuerEmits(t *testing.T) {
	notClaimsAboutTheUser := map[string]string{
		"nonce":     "an echo of the client's own request parameter, bound to this token rather than describing the end user",
		"client_id": "names the audience, not the subject; RFC 9068 calls it a token claim",
		"scope":     "what this token was granted, not a fact about the end user",
	}

	f := setupScopeClaims(t, true)

	// Everything a full grant can produce, from both emitters.
	emitted := map[string]bool{}
	_, access := f.accessToken(t, "openid profile email")
	for k := range access {
		emitted[k] = true
	}
	for k := range f.idToken(t, "openid profile email") {
		emitted[k] = true
	}
	for k := range f.userInfo(t, "openid profile email") {
		emitted[k] = true
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil).WithContext(f.ctx)
	f.svc.handleDiscovery(c)
	if w.Code != http.StatusOK {
		t.Fatalf("discovery: %d %s", w.Code, w.Body.String())
	}
	var doc OIDCDiscovery
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	advertised := map[string]bool{}
	for _, k := range doc.ClaimsSupported {
		advertised[k] = true
	}

	for claim := range emitted {
		if advertised[claim] {
			continue
		}
		if _, registered := notClaimsAboutTheUser[claim]; registered {
			continue
		}
		t.Fatalf("the issuer emits %q but claims_supported does not list it: add it to the list, or register it in this test with the reason it is not a claim about the end user", claim)
	}

	// The list must not advertise what nothing emits either: an advertised
	// claim a relying party never receives is the same defect facing the other
	// way. Claims that only appear with a session or a nonce are named here.
	onlyUnderSomeRequests := map[string]bool{"sid": true, "auth_time": true, "amr": true}
	for claim := range advertised {
		if emitted[claim] || onlyUnderSomeRequests[claim] {
			continue
		}
		t.Fatalf("claims_supported advertises %q but no emitter produces it", claim)
	}
}

// THE CALL SITE, not just the function. The first round of mutation testing
// for this change replaced `authCode.Scope` at the token endpoint with a
// hard-coded "openid profile email" and every test above stayed green: they
// all call GenerateIDToken directly, so the wiring that actually carries the
// grant from the authorization code to the minting function was never
// exercised. A rule that is enforced by a function nothing routes to is the
// same defect this whole change is about, one layer up.
//
// This drives the real grant: a real authorization code row with a real scope,
// consumed by the real handler, and the ID token it hands back.
func TestTheTokenEndpointMintsWithTheScopeOnTheAuthorizationCode(t *testing.T) {
	f := newRefreshGrantFixture(t)
	if _, err := f.db.Pool.Exec(f.ctx, `
		CREATE TABLE oauth_authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id UUID NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			nonce TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL DEFAULT '',
			code_challenge_method VARCHAR(10) NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			org_id UUID NOT NULL
		)`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	exchange := func(t *testing.T, code, scope string) jwt.MapClaims {
		t.Helper()
		if _, err := f.db.Pool.Exec(f.ctx, `
			INSERT INTO oauth_authorization_codes
				(code, client_id, user_id, redirect_uri, scope, expires_at, org_id)
			VALUES ($1, 'app', $2, 'https://rp.test/cb', $3, NOW() + INTERVAL '5 minutes', $4)`,
			code, grantUser, scope, grantOrg); err != nil {
			t.Fatalf("seed code: %v", err)
		}
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {"app"},
			"client_secret": {"s3cret"},
			"redirect_uri":  {"https://rp.test/cb"},
		}
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.Request = req.WithContext(f.ctx)
		f.svc.handleAuthorizationCodeGrant(c)
		if w.Code != http.StatusOK {
			t.Fatalf("token endpoint: %d %s", w.Code, w.Body.String())
		}
		var body struct {
			IDToken string `json:"id_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.IDToken == "" {
			t.Fatal("no id_token in the token response")
		}
		return unverifiedClaims(t, body.IDToken)
	}

	// A code granted the bare openid scope must produce an ID token with no
	// identity claims on it, all the way through the endpoint.
	bare := exchange(t, "code-bare-openid", "openid")
	for _, k := range []string{"email", "email_verified", "name", "given_name", "family_name", "preferred_username"} {
		if v, ok := bare[k]; ok {
			t.Fatalf("the token endpoint minted %q = %v for a code granted only `openid`", k, v)
		}
	}

	// And a code that did ask still gets them, so the gate is a gate and not
	// simply a claim that was dropped everywhere.
	// The values are asserted, not merely the keys: an empty string written
	// under a granted scope is present-and-useless, and reading the fixture's
	// user badly would otherwise pass this test.
	full := exchange(t, "code-full-scope", "openid profile email")
	for k, want := range map[string]interface{}{
		"email":              "grant@test.local",
		"email_verified":     true,
		"name":               "Grant Tester",
		"given_name":         "Grant",
		"family_name":        "Tester",
		"preferred_username": "grant@test.local",
	} {
		got, ok := full[k]
		if !ok {
			t.Fatalf("the token endpoint withheld %q from a code that granted profile and email", k)
		}
		if got != want {
			t.Fatalf("%q = %v, want %v", k, got, want)
		}
	}
}
