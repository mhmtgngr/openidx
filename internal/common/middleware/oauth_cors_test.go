package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func oauthCORSRouter(wildcard bool, origins ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(OAuthCORS(wildcard, origins...))
	r.Any("/*any", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func corsReq(r *gin.Engine, method, path, origin string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	r.ServeHTTP(w, req)
	return w
}

// A public client on a relying party's origin must be able to call the token
// endpoint; that is what PKCE exists for, and there is no origin list an IdP
// could maintain for it. "*" is safe here because it can never carry cookies.
func TestOAuthCORS_ProtocolEndpointsAreWildcard(t *testing.T) {
	r := oauthCORSRouter(true, "https://console.example.com")
	for _, p := range []string{"/oauth/token", "/oauth/introspect", "/oauth/revoke", "/oauth/userinfo",
		"/oauth/device_authorization", "/oauth/register", "/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		w := corsReq(r, http.MethodPost, p, "https://some-relying-party.example")
		assert.Equal(t, http.StatusOK, w.Code, p)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"), p)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"), "wildcard must never be paired with credentials")

		pre := corsReq(r, http.MethodOptions, p, "https://some-relying-party.example")
		assert.Equal(t, http.StatusNoContent, pre.Code, "preflight is answered here, %s", p)
		assert.Equal(t, "*", pre.Header().Get("Access-Control-Allow-Origin"))
	}
}

// The login, MFA and consent pages carry a session; they follow the configured
// list like every other service, and a disallowed origin is refused, not
// reflected.
func TestOAuthCORS_UIPathsFollowTheConfiguredList(t *testing.T) {
	r := oauthCORSRouter(true, "https://console.example.com")

	w := corsReq(r, http.MethodPost, "/oauth/login", "https://console.example.com")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://console.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))

	w = corsReq(r, http.MethodPost, "/oauth/login", "https://evil.example")
	assert.Equal(t, http.StatusForbidden, w.Code, "a session-carrying UI path from an unlisted origin is refused")
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))

	// /oauth/authorize is a top-level navigation, not a fetch; it has no
	// Origin header and must not be touched.
	w = corsReq(r, http.MethodGet, "/oauth/authorize", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// An operator who turns the protocol wildcard off gets the list everywhere —
// the escape hatch for a closed deployment where every relying party is known.
func TestOAuthCORS_WildcardCanBeDisabled(t *testing.T) {
	r := oauthCORSRouter(false, "https://console.example.com")
	w := corsReq(r, http.MethodPost, "/oauth/token", "https://some-relying-party.example")
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = corsReq(r, http.MethodPost, "/oauth/token", "https://console.example.com")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://console.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestIsOAuthProtocolPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/oauth/token":                true,
		"/oauth/token/":               true,
		"/oauth/tokens":               false,
		"/oauth/login":                false,
		"/oauth/mfa-verify":           false,
		"/oauth/authorize":            false,
		"/.well-known/jwks.json":      true,
		"/oauth/jwks":                 true,
		"/oauth/userinfo":             true,
		"/oauth/stepup-verify":        false,
		"/api/v1/oauth/clients":       false,
		"/oauth/device_authorization": true,
	} {
		assert.Equal(t, want, IsOAuthProtocolPath(p), p)
	}
}
