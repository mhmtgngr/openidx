package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
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
	return serveBearerIn(t, h, method, path, bearer, "")
}

// serveBearerIn is serveBearer for a request the tenant resolver scoped to
// orgID ("" for none).
func serveBearerIn(t *testing.T, h gin.HandlerFunc, method, path, bearer, orgID string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	if orgID != "" {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
	}
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

	_, err = svc.validateExchangeToken(context.Background(), idToken)
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
	access[middleware.OrgIDClaim] = middleware.DefaultOrgID
	assert.Equal(t, true, introspect(mintAccessToken(t, access, pk)), "the control: an access token of the same client")
}

// The same endpoints hold an access token to the organization it was minted in:
// a token naming none is refused with the reason (a fresh sign-in replaces
// it), and a token of another organization than the one the request resolved
// to is refused too. Unlike the API validators there is no platform-admin
// crossing here: each of these acts for the token's own subject, whose account
// is in the token's organization only.
func TestTheServicesOwnBearerEndpointsAreBoundToTheTokensOrganization(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()
	const orgA, orgB = "aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-00000000000b"

	access := func(orgID string, roles ...interface{}) string {
		claims := jwt.MapClaims{
			"sub": "user-a", "client_id": "rp-client", "roles": roles,
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		}
		if orgID == "" {
			return mintAccessTokenWithoutOrg(t, claims, pk)
		}
		claims[middleware.OrgIDClaim] = orgID
		return mintAccessToken(t, claims, pk)
	}

	for _, tc := range []struct {
		name, token, resolved, description string
	}{
		{"another organization's token", access(orgA, "admin"), orgB, "token is not valid for this organization"},
		{"a platform admin's token in another organization", access(orgA, "super_admin"), orgB, "token is not valid for this organization"},
		{"a token naming no organization", access(""), orgA, "token has no organization; sign in again"},
	} {
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
			code, body := serveBearerIn(t, ep.handler, ep.method, ep.path, tc.token, tc.resolved)
			assert.Equal(t, http.StatusUnauthorized, code, "%s at %s", tc.name, ep.name)
			assert.Equal(t, tc.description, body["error_description"], "%s at %s", tc.name, ep.name)
		}

		ctx := orgctx.With(context.Background(), orgctx.Org{ID: tc.resolved})
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/oauth/social/link/p/start", nil).WithContext(ctx)
		c.Request.Header.Set("Authorization", "Bearer "+tc.token)
		assert.Empty(t, svc.bearerUserID(c), "%s: social account linking resolved a user", tc.name)

		_, err := svc.extractSAMLUserFromToken(ctx, tc.token)
		assert.Error(t, err, "%s: SAML IdP bearer sign-in", tc.name)

		_, err = svc.validateExchangeToken(ctx, tc.token)
		assert.Error(t, err, "%s: token exchange", tc.name)
	}

	// The control: in its own organization the same token is accepted by the
	// check every one of these endpoints shares, and by token exchange.
	own := access(orgA, "admin")
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	_, err := svc.parseAccessToken(ctxA, own)
	assert.NoError(t, err, "a token of the request's own organization was refused")
	_, err = svc.validateExchangeToken(ctxA, own)
	assert.NoError(t, err, "token exchange refused a subject token of the request's own organization")
}

// Introspection reports a token the API validators would refuse as inactive:
// one naming no organization, and one of another organization than the
// calling client's.
func TestIntrospectionReportsAnotherOrganizationsTokenInactive(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()
	const orgA, orgB = "aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-00000000000b"

	introspectIn := func(orgID, token string) interface{} {
		t.Helper()
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.Request = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
		c.Set(authenticatedClientKey, "rp-client")
		svc.handleIntrospect(c)
		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp["active"]
	}
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "user-a", "client_id": "rp-client", "exp": float64(time.Now().Add(time.Hour).Unix())}
	}
	withOrg := claims()
	withOrg[middleware.OrgIDClaim] = orgA
	tokA := mintAccessToken(t, withOrg, pk)

	assert.Equal(t, true, introspectIn(orgA, tokA), "the control: its own organization")
	assert.Equal(t, false, introspectIn(orgB, tokA), "another organization's token introspected as active")
	assert.Equal(t, false, introspectIn(orgA, mintAccessTokenWithoutOrg(t, claims(), pk)), "a token naming no organization introspected as active")
}

// A third-party application's access token -- valid, of the request's
// organization, and without the API-access claim -- is refused by this
// service's account endpoints: sign-out everywhere, the session policy read,
// social account linking and the SAML IdP's bearer sign-in. The endpoints
// every relying party calls keep accepting it: the check UserInfo makes, and
// introspection by the client it was issued to.
func TestTheServicesAccountEndpointsRefuseATokenWithoutAPIAccess(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()
	thirdParty := mintAccessTokenWithoutOrg(t, jwt.MapClaims{
		"sub": "user-a", "client_id": "rp-client", "roles": []interface{}{"admin"},
		middleware.OrgIDClaim: middleware.DefaultOrgID,
		"exp":                 float64(time.Now().Add(time.Hour).Unix()),
	}, pk)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: middleware.DefaultOrgID})

	for _, ep := range []struct {
		name    string
		handler gin.HandlerFunc
		method  string
		path    string
	}{
		{"logout-all", svc.handleLogoutAll, http.MethodPost, "/oauth/logout-all"},
		{"session-info", svc.handleSessionInfo, http.MethodGet, "/oauth/session-info"},
	} {
		code, body := serveBearerIn(t, ep.handler, ep.method, ep.path, thirdParty, middleware.DefaultOrgID)
		assert.Equal(t, http.StatusUnauthorized, code, "%s accepted a third-party application's token", ep.name)
		assert.Equal(t, "invalid_token", body["error"], ep.name)
		assert.Equal(t, "this application may not call the OpenIDX API", body["error_description"], ep.name)
	}

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/social/link/p/start", nil).WithContext(ctx)
	c.Request.Header.Set("Authorization", "Bearer "+thirdParty)
	assert.Empty(t, svc.bearerUserID(c), "social account linking resolved a user from a third-party application's token")

	_, err := svc.extractSAMLUserFromToken(ctx, thirdParty)
	assert.True(t, errors.Is(err, middleware.ErrNoAPIAccess), "SAML IdP bearer sign-in: err = %v", err)

	_, err = svc.parseAccessToken(ctx, thirdParty)
	assert.NoError(t, err, "the check UserInfo makes refused a relying party's own access token")
	w := postFormAsClient(t, svc.handleIntrospect, url.Values{"token": {thirdParty}}, "rp-client")
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"], "introspection reported a relying party's own access token inactive")
}
