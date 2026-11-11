package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ENTERPRISE SSO AS AN OPENID CONNECT RELYING PARTY (sso_federation.go).
//
// Driven through RegisterRoutes over a migrated database, against an
// httptest provider that publishes a discovery document, a key set and a
// token endpoint.

type ssoRun struct {
	authorize *url.URL // where /oauth/authorize sent the browser
	callback  *httptest.ResponseRecorder
}

// ssoSignIn runs /oauth/authorize?idp_hint= and the provider's callback for
// sub/email with extra ID token claims. A nil extra["nonce"] answers with the
// nonce OpenIDX sent; any other value is sent as is.
func (x *externalHarness) ssoSignIn(sub, email string, extra map[string]interface{}, authorizeExtra url.Values) ssoRun {
	x.t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"admin-console"},
		"redirect_uri": {"http://localhost:3000/login"}, "scope": {"openid"}, "state": {"st-sso"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"idp_hint": {x.idp},
	}
	for k, v := range authorizeExtra {
		q[k] = v
	}
	w := x.get("/oauth/authorize?" + q.Encode())
	if w.Code != http.StatusFound {
		x.t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	claims := map[string]interface{}{}
	for k, v := range extra {
		claims[k] = v
	}
	if _, ok := claims["nonce"]; !ok {
		claims["nonce"] = loc.Query().Get("nonce")
	}
	code := x.provider.codeWith(sub, email, claims)
	return ssoRun{authorize: loc, callback: x.get("/oauth/callback?" + url.Values{"code": {code}, "state": {loc.Query().Get("state")}}.Encode())}
}

func refusedWith(t *testing.T, w *httptest.ResponseRecorder, reason string) {
	t.Helper()
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc.Path != "/login" || loc.Query().Get("error") != reason {
		t.Fatalf("want a redirect to /login?error=%s, got %d %q", reason, w.Code, w.Header().Get("Location"))
	}
}

func issuedCode(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("want a code, got %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestSSOAuthorizeUsesDiscoveryNoncePKCEAndPassThrough(t *testing.T) {
	x := newExternalHarness(t)
	x.exec(`UPDATE identity_providers SET pass_through_params = '{login_hint}' WHERE id = $1::uuid`, x.idp)
	run := x.ssoSignIn("nobody", "nobody@example.test", nil, url.Values{"login_hint": {"a@b.test"}, "prompt": {"login"}})
	a := run.authorize
	if !strings.HasSuffix(a.Path, "/protocol/openid-connect/auth") || !strings.HasPrefix(a.String(), x.provider.srv.URL) {
		t.Fatalf("authorize endpoint not from discovery: %s", a)
	}
	for _, p := range []string{"state", "nonce", "code_challenge"} {
		if a.Query().Get(p) == "" {
			t.Fatalf("upstream request carries no %s: %s", p, a)
		}
	}
	if a.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", a.Query().Get("code_challenge_method"))
	}
	if a.Query().Get("login_hint") != "a@b.test" || a.Query().Get("prompt") != "" {
		t.Fatalf("pass-through: login_hint=%q prompt=%q, want only login_hint", a.Query().Get("login_hint"), a.Query().Get("prompt"))
	}
}

func TestSSOCallbackRefusesANonceMismatch(t *testing.T) {
	x := newExternalHarness(t)
	user := x.seedUser(middleware.DefaultOrgID, "sso-nonce")
	sub := "sso-nonce-" + x.suffix
	x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, sub, user)
	run := x.ssoSignIn(sub, "", map[string]interface{}{"nonce": "not-the-one-sent"}, nil)
	refusedWith(t, run.callback, ssoErrNonceMismatch)
	if n := x.codes(user); n != 0 {
		t.Fatalf("%d codes after a nonce mismatch", n)
	}
}

func TestSSOCallbackUpstreamErrorGoesToLogin(t *testing.T) {
	x := newExternalHarness(t)
	q := url.Values{
		"response_type": {"code"}, "client_id": {"admin-console"},
		"redirect_uri": {"http://localhost:3000/login"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"idp_hint": {x.idp}, "login_session": {"ls-1"},
	}
	w := x.get("/oauth/authorize?" + q.Encode())
	loc, _ := url.Parse(w.Header().Get("Location"))
	cb := x.get("/oauth/callback?" + url.Values{"error": {"access_denied"}, "state": {loc.Query().Get("state")}}.Encode())
	refusedWith(t, cb, ssoErrIdP)
	if l, _ := url.Parse(cb.Header().Get("Location")); l.Query().Get("login_session") != "ls-1" {
		t.Fatalf("login_session not carried back: %q", cb.Header().Get("Location"))
	}
}

func TestSSOCallbackDoesNotMatchAnEmailSubstring(t *testing.T) {
	x := newExternalHarness(t)
	victim := x.seedUser(middleware.DefaultOrgID, "alice-admin")
	victimEmail := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, victim)
	// The provider vouches for a verified address that is a substring of
	// the victim's; the old ListUsers search matched it.
	partial := strings.TrimPrefix(victimEmail, "alice-")
	run := x.ssoSignIn("attacker-"+x.suffix, partial, map[string]interface{}{"email_verified": true}, nil)
	refusedWith(t, run.callback, ssoErrUserNotFound)
	if n := x.codes(victim); n != 0 {
		t.Fatalf("a substring email signed in as the victim: %d codes", n)
	}

	// An unverified exact email does not link either.
	run = x.ssoSignIn("attacker2-"+x.suffix, victimEmail, nil, nil)
	refusedWith(t, run.callback, ssoErrUserNotFound)

	// A verified exact email links, and the link is written.
	run = x.ssoSignIn("alice-sub-"+x.suffix, victimEmail, map[string]interface{}{"email_verified": true}, nil)
	issuedCode(t, run.callback)
	if got := x.scalar(`SELECT COALESCE(external_user_id,'') FROM users WHERE id = $1::uuid`, victim); got != "alice-sub-"+x.suffix {
		t.Fatalf("link not backfilled: %q", got)
	}
}

func TestSSOCallbackPrefersOIDOverEmail(t *testing.T) {
	x := newExternalHarness(t)
	x.exec(`UPDATE identity_providers SET external_id_claim = 'oid' WHERE id = $1::uuid`, x.idp)
	byOID := x.seedUser(middleware.DefaultOrgID, "oid-owner")
	byEmail := x.seedUser(middleware.DefaultOrgID, "email-owner")
	oid := "00000000-oid-" + x.suffix
	x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, oid, byOID)
	email := x.scalar(`SELECT email FROM users WHERE id = $1::uuid`, byEmail)

	run := x.ssoSignIn("pairwise-sub", email, map[string]interface{}{"oid": oid, "email_verified": true}, nil)
	issuedCode(t, run.callback)
	if x.codes(byOID) != 1 || x.codes(byEmail) != 0 {
		t.Fatalf("codes: oid owner %d, email owner %d; want 1, 0", x.codes(byOID), x.codes(byEmail))
	}
}

func TestSSOCallbackJITOnlyWhenTheIdPProvisions(t *testing.T) {
	x := newExternalHarness(t)
	email := "jit-" + x.suffix + "@example.test"
	run := x.ssoSignIn("jit-"+x.suffix, email, map[string]interface{}{"email_verified": true}, nil)
	refusedWith(t, run.callback, ssoErrUserNotFound)

	x.exec(`UPDATE identity_providers SET jit_policy = '{"provision":true,"population":"external"}' WHERE id = $1::uuid`, x.idp)
	run = x.ssoSignIn("jit-"+x.suffix, email, map[string]interface{}{"email_verified": true}, nil)
	refusedWith(t, run.callback, ssoErrPartnerNotRegistered)

	x.exec(`UPDATE identity_providers SET jit_policy = '{"provision":true,"population":"internal"}' WHERE id = $1::uuid`, x.idp)
	run = x.ssoSignIn("jit-"+x.suffix, email, map[string]interface{}{"email_verified": true}, nil)
	issuedCode(t, run.callback)
	if got := x.scalar(`SELECT COALESCE(external_user_id,'') FROM users WHERE lower(email) = lower($1)`, email); got != "jit-"+x.suffix {
		t.Fatalf("provisioned user not linked: %q", got)
	}
}

func TestSSOCallbackSyncsOnlyMappedGroups(t *testing.T) {
	x := newExternalHarness(t)
	org := middleware.DefaultOrgID
	user := x.seedUser(org, "grp")
	sub := "grp-" + x.suffix
	x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, sub, user)
	mappedIn := x.scalar(`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, "eng-"+x.suffix)
	mappedOut := x.scalar(`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, "ops-"+x.suffix)
	unmapped := x.scalar(`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, "local-"+x.suffix)
	for _, g := range []string{mappedOut, unmapped} {
		x.exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, user, g, org)
	}
	x.exec(`UPDATE identity_providers SET group_mapping = jsonb_build_array(
		jsonb_build_object('claim_value','Engineering','group_id',$2::text),
		jsonb_build_object('claim_value','Operations','group_id',$3::text)) WHERE id = $1::uuid`, x.idp, mappedIn, mappedOut)

	run := x.ssoSignIn(sub, "", map[string]interface{}{"groups": []string{"Engineering", "Unrelated"}}, nil)
	issuedCode(t, run.callback)
	member := func(g string) bool {
		return x.scalar(`SELECT EXISTS (SELECT 1 FROM group_memberships WHERE user_id = $1::uuid AND group_id = $2::uuid)::text`, user, g) == "true"
	}
	if !member(mappedIn) || member(mappedOut) || !member(unmapped) {
		t.Fatalf("memberships: mapped-in %v, mapped-out %v, unmapped %v; want true false true", member(mappedIn), member(mappedOut), member(unmapped))
	}
}

func TestSSOTrustUpstreamMFAOnlyForInternalUsers(t *testing.T) {
	x := newExternalHarness(t)
	org := middleware.DefaultOrgID
	x.exec(`UPDATE identity_providers SET trust_upstream_mfa = true WHERE id = $1::uuid`, x.idp)
	withTOTP := func(user string) {
		key, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: user})
		x.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id) VALUES ($1::uuid, $2, true, NOW(), $3::uuid)`, user, key.Secret(), org)
	}

	internal := x.seedUser(org, "trust-int")
	isub := "trust-int-" + x.suffix
	x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, isub, internal)
	withTOTP(internal)

	// Without an upstream MFA amr the internal user still gives a factor.
	handedToSecondFactor(t, x.ssoSignIn(isub, "", map[string]interface{}{"amr": []string{"pwd"}}, nil).callback, "totp")

	run := x.ssoSignIn(isub, "", map[string]interface{}{"amr": []string{"pwd", "mfa"}}, nil)
	issuedCode(t, run.callback)
	if got := x.scalar(`SELECT array_to_string(auth_methods, ',') FROM sessions WHERE user_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, internal); got != "fed,mfa" {
		t.Fatalf("session auth_methods = %q, want fed,mfa", got)
	}

	sponsor := x.seedUser(org, "trust-sponsor")
	vendor := x.scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, "Acme "+x.suffix)
	esub := "trust-ext-" + x.suffix
	external := x.scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, enabled, idp_id, external_user_id)
		VALUES ($1::uuid, $2::text, $2::text || '@supplier.example.test', 'external', $3::uuid, $4::uuid, NOW() + interval '30 days', true, $5::uuid, $6)
		RETURNING id::text`, org, "trust-ext-"+x.suffix, vendor, sponsor, x.idp, esub)
	withTOTP(external)
	handedToSecondFactor(t, x.ssoSignIn(esub, "", map[string]interface{}{"amr": []string{"mfa"}}, nil).callback, "totp")
	if n := x.codes(external); n != 0 {
		t.Fatalf("an external user skipped the OpenIDX factor on upstream MFA: %d codes", n)
	}
}

func TestSSOIDTokenCarriesTheIdP(t *testing.T) {
	x := newExternalHarness(t)
	user := x.seedUser(middleware.DefaultOrgID, "idp-claim")
	sub := "idp-claim-" + x.suffix
	x.exec(`UPDATE users SET idp_id = $1::uuid, external_user_id = $2 WHERE id = $3::uuid`, x.idp, sub, user)
	issuedCode(t, x.ssoSignIn(sub, "", nil, nil).callback)
	sid := x.scalar(`SELECT id::text FROM sessions WHERE user_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, user)
	if got := x.scalar(`SELECT array_to_string(auth_methods, ',') FROM sessions WHERE id = $1::uuid`, sid); got != "fed" {
		t.Fatalf("auth_methods = %q, want fed", got)
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: middleware.DefaultOrgID})
	raw, err := x.issuer.GenerateIDToken(ctx, user, "admin-console", "", "openid", 60, sid)
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := tok.Claims.(jwt.MapClaims)["idp"]; got != x.idp {
		t.Fatalf("idp claim = %v, want %s", got, x.idp)
	}
}
