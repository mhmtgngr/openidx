package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/middleware"
)

// adminIDTokenClaims is an administrator's ID token as GenerateIDToken builds
// one: the roles and permissions an API authorizes on, an audience naming the
// relying party it was issued to, and no client_id.
func adminIDTokenClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":         "user-admin",
		"aud":         "rp-client",
		"roles":       []interface{}{"admin"},
		"permissions": []interface{}{"users:write"},
		"iat":         float64(time.Now().Unix()),
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
}

func serveBearer(t *testing.T, h gin.HandlerFunc, method, path, bearer string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	c.Request.Header.Set("Authorization", "Bearer "+bearer)
	h(c)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// Every endpoint of this service that acts for a bearer's subject refuses an ID
// token, which verifies against the same key: userinfo (OIDC Core §5.3 takes
// an access token), sign-out-everywhere, the session policy read, social
// account linking, the SAML IdP's bearer sign-in and token exchange. Each is
// refused before anything is looked up, which is why no database is needed.
func TestTheServicesOwnBearerEndpointsRefuseAnIDToken(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()
	idToken := mintToken(t, adminIDTokenClaims(), pk)

	for _, ep := range []struct {
		name    string
		handler gin.HandlerFunc
		method  string
		path    string
	}{
		{"userinfo", svc.handleUserInfo, http.MethodGet, "/oauth/userinfo"},
		{"logout-all", svc.handleLogoutAll, http.MethodPost, "/oauth/logout-all"},
		{"session-info", svc.handleSessionInfo, http.MethodGet, "/oauth/session-info"},
	} {
		code, body := serveBearer(t, ep.handler, ep.method, ep.path, idToken)
		assert.Equal(t, http.StatusUnauthorized, code, "%s accepted an ID token", ep.name)
		assert.Equal(t, "invalid_token", body["error"], ep.name)
		assert.Equal(t, "not an access token", body["error_description"], ep.name)
	}

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/social/link/p/start", nil)
	c.Request.Header.Set("Authorization", "Bearer "+idToken)
	assert.Empty(t, svc.bearerUserID(c), "social account linking resolved a user from an ID token")

	_, err := svc.extractSAMLUserFromToken(context.Background(), idToken)
	assert.True(t, errors.Is(err, middleware.ErrNotAccessToken), "SAML IdP bearer sign-in: err = %v", err)

	_, err = svc.validateExchangeToken(idToken)
	assert.True(t, errors.Is(err, middleware.ErrNotAccessToken), "token exchange: err = %v", err)
}

// Introspection answers for access and refresh tokens. An ID token, although
// its audience names the calling client, is reported the way an unknown token
// is, so that a resource server relying on introspection does not accept it as
// a bearer.
func TestIntrospectionReportsAnIDTokenInactive(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	introspect := func(token string) interface{} {
		t.Helper()
		w := postFormAsClient(t, svc.handleIntrospect, url.Values{"token": {token}}, "rp-client")
		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp["active"]
	}

	assert.Equal(t, false, introspect(mintToken(t, adminIDTokenClaims(), pk)), "an ID token introspected as active")

	access := adminIDTokenClaims()
	access["client_id"] = "rp-client"
	assert.Equal(t, true, introspect(mintAccessToken(t, access, pk)), "the control: an access token of the same client")
}
