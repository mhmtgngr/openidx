package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// These tests need no database: they pin the parts of the SSO fast path that
// decide BEFORE a session is looked up (prompt / max_age parsing, the
// no-cookie and unresolvable-cookie branches, the logout half's Redis and
// cookie work). The session-backed half lives in browser_session_db_test.go.

const ssoTestRedirect = "https://app.example.test/callback"
const ssoTestOrg = "11111111-1111-1111-1111-111111111111"

func ssoTestClient() *OAuthClient {
	return &OAuthClient{ClientID: "c", Type: "public", RedirectURIs: []string{ssoTestRedirect}, Scopes: []string{"openid", "profile", "email"}}
}

// ssoAuthorize performs GET /oauth/authorize with the standard valid parameters
// plus extra, optionally carrying an openidx_sso cookie, under tenant ssoTestOrg.
func ssoAuthorize(t *testing.T, svc *Service, cookie string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	q := url.Values{
		"client_id":     {"c"},
		"redirect_uri":  {ssoTestRedirect},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"st-1"},
		// ssoTestClient is a public client, and /oauth/authorize now holds
		// public clients to RFC 7636 (pkce_policy.go). These cases are about
		// what the browser session does with a request, so they carry a valid
		// challenge rather than exercising the refusal — the refusal has its
		// own table in pkce_policy_test.go.
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: cookie})
	}
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
	svc.handleAuthorize(c)
	return w
}

// locationOf parses the 302 Location, failing the test on anything else.
func locationOf(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad Location %q: %v", w.Header().Get("Location"), err)
	}
	return u
}

// clearedSSOCookie reports whether the response tells the browser to drop
// openidx_sso (Max-Age<=0 / empty value).
func clearedSSOCookie(w *httptest.ResponseRecorder) bool {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == ssoCookieName && ck.Value == "" && ck.MaxAge < 0 {
			return true
		}
	}
	return false
}

// setSSOCookie returns the openidx_sso cookie a response sets (non-empty), or nil.
func setSSOCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == ssoCookieName && ck.Value != "" {
			return ck
		}
	}
	return nil
}

func TestParsePrompt(t *testing.T) {
	cases := []struct {
		in      string
		want    authorizePrompt
		wantErr bool
	}{
		{"", authorizePrompt{}, false},
		{"none", authorizePrompt{None: true}, false},
		{"login", authorizePrompt{Login: true}, false},
		{"consent select_account", authorizePrompt{Consent: true, SelectAccount: true}, false},
		{"login consent", authorizePrompt{Login: true, Consent: true}, false},
		{"none login", authorizePrompt{}, true},
		{"login none", authorizePrompt{}, true},
		{"NONE", authorizePrompt{}, true},   // case-sensitive per spec
		{"create", authorizePrompt{}, true}, // not implemented: refuse rather than pretend
	}
	for _, tc := range cases {
		got, err := parsePrompt(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parsePrompt(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parsePrompt(%q)=%+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestParseMaxAge(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantSet bool
		wantErr bool
	}{
		{"", 0, false, false},
		{"0", 0, true, false},
		{"3600", time.Hour, true, false},
		{" 60 ", time.Minute, true, false},
		{"-1", 0, false, true},
		{"abc", 0, false, true},
		{"1.5", 0, false, true},
	}
	for _, tc := range cases {
		got, set, err := parseMaxAge(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseMaxAge(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if got != tc.want || set != tc.wantSet {
			t.Errorf("parseMaxAge(%q)=(%v,%v), want (%v,%v)", tc.in, got, set, tc.want, tc.wantSet)
		}
	}
}

// Control: with no cookie and no prompt the endpoint behaves exactly as it
// did before SSO existed — a redirect to the login UI carrying login_session.
func TestAuthorizeWithoutCookieStillRedirectsToLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	u := locationOf(t, ssoAuthorize(t, svc, "", nil))
	if u.Host != "openidx.tdv.org" || u.Path != "/login" || u.Query().Get("login_session") == "" {
		t.Fatalf("expected the login UI with a login_session, got %s", u)
	}
	if clearedSSOCookie(ssoAuthorize(t, svc, "", nil)) {
		t.Fatal("no cookie was sent; none should be cleared")
	}
}

// OIDC Core §3.1.2.6: prompt=none with no authenticated user is answered at
// the redirect_uri as login_required, with state, never with a login page.
func TestAuthorizePromptNoneWithoutSessionIsLoginRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	u := locationOf(t, ssoAuthorize(t, svc, "", url.Values{"prompt": {"none"}}))
	if u.Host != "app.example.test" || u.Path != "/callback" {
		t.Fatalf("expected the client's redirect_uri, got %s", u)
	}
	if got := u.Query().Get("error"); got != ErrorLoginRequired {
		t.Fatalf("error=%q, want %q (%s)", got, ErrorLoginRequired, u)
	}
	if u.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %s", u)
	}
}

// Malformed prompt / max_age are the CLIENT's errors (invalid_request at its
// validated redirect_uri), not a login page for a user who cannot fix them.
func TestAuthorizeMalformedPromptOrMaxAgeIsInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	for name, extra := range map[string]url.Values{
		"prompt=none login": {"prompt": {"none login"}},
		"prompt=unknown":    {"prompt": {"create"}},
		"max_age=abc":       {"max_age": {"abc"}},
		"max_age=-5":        {"max_age": {"-5"}},
	} {
		t.Run(name, func(t *testing.T) {
			u := locationOf(t, ssoAuthorize(t, svc, "", extra))
			if u.Host != "app.example.test" {
				t.Fatalf("expected the client's redirect_uri, got %s", u)
			}
			if got := u.Query().Get("error"); got != ErrorInvalidRequest {
				t.Fatalf("error=%q, want invalid_request (%s)", got, u)
			}
		})
	}
}

// A cookie this service cannot resolve (here: no database at all) is cleared
// so the browser stops presenting it, and the request proceeds to the login
// UI as if there had been no cookie.
func TestAuthorizeUnresolvableCookieIsClearedAndFallsBackToLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	token := GenerateRandomToken(32)
	w := ssoAuthorize(t, svc, token, nil)
	u := locationOf(t, w)
	if u.Path != "/login" {
		t.Fatalf("expected the login UI, got %s", u)
	}
	if !clearedSSOCookie(w) {
		t.Fatalf("a cookie that resolves to nothing must be cleared; Set-Cookie=%v", w.Header().Values("Set-Cookie"))
	}

	// Same shape under prompt=none: login_required, and still cleared.
	w = ssoAuthorize(t, svc, token, url.Values{"prompt": {"none"}})
	if u := locationOf(t, w); u.Query().Get("error") != ErrorLoginRequired {
		t.Fatalf("prompt=none with a dead cookie must be login_required, got %s", u)
	}
	if !clearedSSOCookie(w) {
		t.Fatal("dead cookie not cleared under prompt=none")
	}
}

// A malformed cookie value never reaches Redis.
func TestAuthorizeGarbageCookieIsIgnored(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	w := ssoAuthorize(t, svc, "not a token", nil)
	if u := locationOf(t, w); u.Path != "/login" {
		t.Fatalf("expected the login UI, got %s", u)
	}
	if !clearedSSOCookie(w) {
		t.Fatal("garbage cookie must be cleared")
	}
}

// /oauth/logout with nothing but the SSO cookie: the Redis mapping is
// deleted and the cookie cleared, so the next /oauth/authorize cannot ride it.
func TestLogoutEndsBrowserSessionMappingAndClearsCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())
	ctx := context.Background()
	token := GenerateRandomToken(32)
	if err := svc.redis.Client.Set(ctx, ssoRedisPrefix+token, "22222222-2222-2222-2222-222222222222", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: token})
	c.Request = req.WithContext(orgctx.With(ctx, orgctx.Org{ID: ssoTestOrg}))
	svc.handleLogout(c)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "logged_out") {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if !clearedSSOCookie(w) {
		t.Fatalf("logout must clear the SSO cookie; Set-Cookie=%v", w.Header().Values("Set-Cookie"))
	}
	if n, _ := svc.redis.Client.Exists(ctx, ssoRedisPrefix+token).Result(); n != 0 {
		t.Fatal("logout must delete the sso_session mapping")
	}
}
