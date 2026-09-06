package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// RFC 6749 §4.1.2.1: once redirect_uri is validated, an /authorize failure is
// reported to the CLIENT by redirecting to it — not rendered for a user who
// cannot act on it. These pin the shape, including that `state` round-trips so
// the client can correlate the failure with its own request.
func TestRedirectAuthorizeError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{}

	t.Run("error, description and state reach the client", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

		svc.redirectAuthorizeError(c, "https://app.example.org/cb", "st-42",
			ErrorInvalidScope, "one or more requested scopes are not registered for this client")

		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("Location is not a URL: %v", err)
		}
		if loc.Scheme != "https" || loc.Host != "app.example.org" || loc.Path != "/cb" {
			t.Fatalf("redirected somewhere other than the registered URI: %s", loc)
		}
		q := loc.Query()
		if q.Get("error") != ErrorInvalidScope {
			t.Errorf("error = %q, want %q", q.Get("error"), ErrorInvalidScope)
		}
		if q.Get("error_description") == "" {
			t.Error("error_description is empty; the client is told something failed but not what")
		}
		if q.Get("state") != "st-42" {
			t.Errorf("state = %q, want it echoed back", q.Get("state"))
		}
	})

	t.Run("existing query parameters on the redirect_uri survive", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

		svc.redirectAuthorizeError(c, "https://app.example.org/cb?tenant=acme", "",
			ErrorInvalidScope, "nope")

		q, _ := url.Parse(w.Header().Get("Location"))
		if q.Query().Get("tenant") != "acme" {
			t.Errorf("clobbered the client's own query: %s", w.Header().Get("Location"))
		}
		if _, present := q.Query()["state"]; present {
			t.Error("state was absent from the request; sending an empty one invents a value")
		}
	})

	t.Run("an unparseable redirect_uri answers in-band rather than redirecting", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

		svc.redirectAuthorizeError(c, "://not a url", "", ErrorInvalidScope, "nope")

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 — there is nowhere safe to redirect", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("redirected to %q anyway", loc)
		}
	})
}

// The check that made the integration suite's long-vacuous assertion real: a
// scope the client is not registered for must be refused, and one it is must
// pass. scopeAllowedForClient is the shared rule; this pins that /authorize's
// notion of "allowed" is that rule and not a second opinion.
func TestScopeAllowedForClientAtAuthorize(t *testing.T) {
	client := &OAuthClient{Scopes: []string{"openid", "profile", "email"}}
	for _, tc := range []struct {
		scope string
		want  bool
	}{
		{"", true},
		{"openid", true},
		{"openid profile email", true},
		{"invalid scope", false},
		{"openid admin", false},
		{"admin", false},
	} {
		if got := scopeAllowedForClient(client, tc.scope); got != tc.want {
			t.Errorf("scopeAllowedForClient(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
}
