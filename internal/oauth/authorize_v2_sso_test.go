package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// /oauth/authorize/v2 is the endpoint the mobile authenticator's browser-login
// fallback opens. Until this file existed its handler carried the comment
// "would be from session cookie / for now, redirect to login" and did exactly
// that for every request — while the login it redirected to set the
// openidx_sso cookie through the shared /oauth/login path. The cookie was
// issued to these browsers and never read. These tests pin parity with the
// primary endpoint: the same fast path, the same gates, the same fallbacks.

// v2Authorize performs GET /oauth/authorize/v2 through the AuthorizeHandler
// with a PKCE challenge (the test client is public, so PKCE is required).
func v2Authorize(t *testing.T, svc *Service, cookie string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAuthorizeHandler(svc, zap.NewNop())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	q := url.Values{
		"client_id":             {"c"},
		"redirect_uri":          {ssoTestRedirect},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"st-1"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/v2?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: cookie})
	}
	c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg}))
	h.HandleAuthorizeRequest(c)
	return w
}

func TestAuthorizeV2LiveSessionMintsCodeWithoutLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	userID := uuid.New().String()
	sessionID, token := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

	w := v2Authorize(t, svc, token, nil)
	code := mintedCode(t, db, w, userID)
	if got, _ := svc.redis.Client.Get(context.Background(), "authcode_session:"+code).Result(); got != sessionID {
		t.Fatalf("authcode_session=%q, want %q", got, sessionID)
	}
	// The PKCE challenge travels with the code, as it does on the login path.
	var challenge, method string
	_ = db.Pool.QueryRow(context.Background(),
		`SELECT code_challenge, code_challenge_method FROM oauth_authorization_codes WHERE code=$1`, code).Scan(&challenge, &method)
	if challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" || method != "S256" {
		t.Fatalf("PKCE not carried: challenge=%q method=%q", challenge, method)
	}
	// No login_session was started for a request that needed no login.
	if keys, _ := svc.redis.Client.Keys(context.Background(), "login_session:*").Result(); len(keys) != 0 {
		t.Fatalf("a login session was started although the code was issued from the cookie: %v", keys)
	}
}

// Every shape the primary endpoint sends to the login UI, v2 sends there too,
// and clears a cookie that resolves to nothing.
func TestAuthorizeV2StaleOrAbsentSessionGoesToLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	userID := uuid.New().String()

	expectV2Login := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		u := locationOf(t, w)
		if u.Path != "/login" || u.Query().Get("login_session") == "" {
			t.Fatalf("expected the login UI with a login_session, got %s", u)
		}
	}

	// Control: no cookie behaves exactly as before.
	w := v2Authorize(t, svc, "", nil)
	expectV2Login(t, w)
	if clearedSSOCookie(w) {
		t.Fatal("no cookie was sent; none should be cleared")
	}

	_, revoked := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, true)
	w = v2Authorize(t, svc, revoked, nil)
	expectV2Login(t, w)
	if !clearedSSOCookie(w) {
		t.Fatal("a revoked session's cookie must be cleared")
	}

	_, live := ssoSession(t, svc, db, ssoTestOrg, userID, 2*time.Hour, 20*time.Hour, false)
	// prompt=login ignores the live session; max_age older than the session
	// re-authenticates; both keep the cookie.
	for name, extra := range map[string]url.Values{
		"prompt=login": {"prompt": {"login"}},
		"max_age=60":   {"max_age": {"60"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := v2Authorize(t, svc, live, extra)
			expectV2Login(t, w)
			if clearedSSOCookie(w) {
				t.Fatal("a live session's cookie must stay")
			}
		})
	}

	var n int
	_ = db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_authorization_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d codes minted without a usable session", n)
	}
}

// OIDC Core §3.1.2.6 at the v2 endpoint: prompt=none without a session is
// login_required at the redirect_uri; malformed prompt / max_age are
// invalid_request there. No database is needed for either.
func TestAuthorizeV2PromptErrorsGoToTheClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", ssoTestClient())

	u := locationOf(t, v2Authorize(t, svc, "", url.Values{"prompt": {"none"}}))
	if u.Host != "app.example.test" || u.Query().Get("error") != ErrorLoginRequired || u.Query().Get("state") != "st-1" {
		t.Fatalf("prompt=none without a session: want login_required with state at the client, got %s", u)
	}
	for name, extra := range map[string]url.Values{
		"prompt=none login": {"prompt": {"none login"}},
		"max_age=abc":       {"max_age": {"abc"}},
	} {
		t.Run(name, func(t *testing.T) {
			u := locationOf(t, v2Authorize(t, svc, "", extra))
			if u.Host != "app.example.test" || u.Query().Get("error") != ErrorInvalidRequest {
				t.Fatalf("want invalid_request at the client, got %s", u)
			}
		})
	}
}
