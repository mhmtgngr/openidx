package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// These tests describe the OpenID Connect discovery document this server
// actually serves.
//
// They used to describe a different one. internal/oauth/discovery.go held a
// second discovery implementation -- a DiscoveryDocument struct, a
// buildDiscoveryDocument, a DiscoveryHandler -- that no service ever mounted,
// and this file was 415 lines proving it correct. tools/routereach found the
// handler with no router. The two documents had drifted, and because the tests
// covered the dead one, the drift was invisible: the SERVED document omitted
// revocation_endpoint and introspection_endpoint (both routed) and omitted
// "none" from token_endpoint_auth_methods_supported (public clients exist and
// the token endpoint skips secret verification for them).
//
// So the dead implementation is deleted and the assertions moved onto the live
// handler. A discovery test that does not go through the route a relying party
// fetches is a test of prose.

// serveDiscovery renders the live discovery document the way a relying party
// gets it: through the router, on the well-known path.
func serveDiscovery(t *testing.T, issuer string) (map[string]interface{}, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	svc := &Service{issuer: issuer, logger: zap.NewNop()}
	router := gin.New()
	router.GET("/.well-known/openid-configuration", svc.handleDiscovery)
	router.OPTIONS("/.well-known/openid-configuration", svc.handleDiscovery)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	return doc, w
}

func strs(t *testing.T, doc map[string]interface{}, key string) []string {
	t.Helper()
	raw, ok := doc[key]
	require.True(t, ok, "discovery document has no %s", key)
	list, ok := raw.([]interface{})
	require.True(t, ok, "%s is not an array", key)
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		require.True(t, ok, "%s contains a non-string", key)
		out = append(out, s)
	}
	return out
}

// Every field OpenID Connect Discovery 1.0 §3 marks REQUIRED is present and
// non-empty. A missing one makes the document unusable to a conforming client.
func TestDiscoveryDocumentHasEveryRequiredField(t *testing.T) {
	const issuer = "https://test.openidx.org"
	doc, _ := serveDiscovery(t, issuer)

	for _, key := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		v, _ := doc[key].(string)
		assert.NotEmpty(t, v, "%s is required by OIDC Discovery 1.0 §3", key)
	}
	for _, key := range []string{
		"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
	} {
		assert.NotEmpty(t, strs(t, doc, key), "%s is required by OIDC Discovery 1.0 §3", key)
	}

	assert.Equal(t, issuer, doc["issuer"])
	assert.Equal(t, issuer+"/oauth/authorize", doc["authorization_endpoint"])
	assert.Equal(t, issuer+"/oauth/token", doc["token_endpoint"])
	assert.Equal(t, issuer+"/.well-known/jwks.json", doc["jwks_uri"])
	assert.Equal(t, issuer+"/oauth/userinfo", doc["userinfo_endpoint"])
}

// Every endpoint the document advertises is one this server routes. The
// converse -- an endpoint routed and not advertised -- is the defect this file
// was rewritten over, so both directions are named here rather than assumed.
func TestDiscoveryAdvertisesTheEndpointsTheServerRoutes(t *testing.T) {
	const issuer = "https://test.openidx.org"
	doc, _ := serveDiscovery(t, issuer)

	for key, path := range map[string]string{
		"authorization_endpoint":        "/oauth/authorize",
		"token_endpoint":                "/oauth/token",
		"userinfo_endpoint":             "/oauth/userinfo",
		"registration_endpoint":         "/oauth/register",
		"device_authorization_endpoint": "/oauth/device_authorization",
		"end_session_endpoint":          "/oauth/logout",
		// RFC 8414 §2. Both were routed and neither was advertised, so a
		// relying party looking for where to revoke a token at sign-out found
		// nowhere -- and did not revoke.
		"revocation_endpoint":    "/oauth/revoke",
		"introspection_endpoint": "/oauth/introspect",
	} {
		assert.Equal(t, issuer+path, doc[key], "%s must point at the route this server serves", key)
	}
}

// The rule this repository keeps returning to: advertised means working.
func TestDiscoveryAdvertisesOnlyImplementedFlows(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")

	responseTypes := strs(t, doc, "response_types_supported")
	assert.Contains(t, responseTypes, "code")
	for _, unimplemented := range []string{"id_token", "token id_token", "code id_token", "code token", "code id_token token"} {
		assert.NotContains(t, responseTypes, unimplemented,
			"advertised %q but the authorize path always issues a code", unimplemented)
	}

	grants := strs(t, doc, "grant_types_supported")
	for _, required := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		assert.Contains(t, grants, required)
	}
	assert.Contains(t, grants, "urn:ietf:params:oauth:grant-type:device_code")
	assert.NotContains(t, grants, "password",
		"the token endpoint has no password case; advertising it returns unsupported_grant_type")

	// PKCE: S256 only. "plain" offers no protection against code interception
	// and the authorize endpoint rejects it in production.
	assert.Equal(t, []string{"S256"}, strs(t, doc, "code_challenge_methods_supported"))
}

// Public clients exist here -- dcr.go registers one when
// token_endpoint_auth_method=none, and the token endpoint skips secret
// verification for that type -- so "none" belongs in the advertised methods.
// Omitting it told every conforming SPA and native client that it had no usable
// authentication method at this server.
func TestDiscoveryAdvertisesPublicClientAuthentication(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")
	methods := strs(t, doc, "token_endpoint_auth_methods_supported")
	assert.Contains(t, methods, "client_secret_basic", "RFC 6749 §2.3.1 requires HTTP Basic")
	assert.Contains(t, methods, "client_secret_post")
	assert.Contains(t, methods, "none", "public clients authenticate with PKCE and no secret")
}

// Only the subject types the provider honours. pairwise appears when
// OIDCPairwiseSubjects is on and not before.
func TestDiscoverySubjectTypesFollowTheConfiguration(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")
	assert.Equal(t, []string{"public"}, strs(t, doc, "subject_types_supported"))
}

// The signing algorithms advertised are the ones tokens are actually signed
// with. RS256 is what the signer produces; listing RS384/RS512 beside it would
// invite a client to demand a signature this server cannot make.
func TestDiscoverySigningAlgorithms(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")
	assert.Equal(t, []string{"RS256"}, strs(t, doc, "id_token_signing_alg_values_supported"))
}

func TestDiscoveryScopesAndClaims(t *testing.T) {
	doc, _ := serveDiscovery(t, "https://test.openidx.org")

	scopes := strs(t, doc, "scopes_supported")
	assert.Contains(t, scopes, "openid", "openid is required for OIDC")
	for _, s := range []string{"profile", "email", "offline_access"} {
		assert.Contains(t, scopes, s)
	}

	claims := strs(t, doc, "claims_supported")
	for _, c := range []string{"sub", "iss", "aud", "exp", "iat", "email", "sid"} {
		assert.Contains(t, claims, c)
	}
}

// The document is cacheable and answers a CORS preflight, because a browser
// client fetches it cross-origin before it can do anything else.
func TestDiscoveryCachingAndPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{issuer: "https://test.openidx.org", logger: zap.NewNop()}
	router := gin.New()
	router.GET("/.well-known/openid-configuration", svc.handleDiscovery)
	router.OPTIONS("/.well-known/openid-configuration", svc.handleDiscovery)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))

	pre := httptest.NewRecorder()
	router.ServeHTTP(pre, httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil))
	assert.Equal(t, http.StatusNoContent, pre.Code)
}

// A tenant fetching discovery from its own host gets its own issuer, so the
// document matches the iss its tokens carry.
func TestDiscoveryIsPerTenantWhenSubdomainTenancyIsOn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{issuer: "https://id.example.com", tenantBaseDomain: "example.com", logger: zap.NewNop()}
	router := gin.New()
	router.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(),
			orgctx.Org{ID: "00000000-0000-0000-0000-000000000010", Slug: "acme"}))
		svc.handleDiscovery(c)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "https://acme.example.com", doc["issuer"])
	assert.Equal(t, "https://acme.example.com/oauth/revoke", doc["revocation_endpoint"],
		"every endpoint moves with the issuer, or the document describes two servers")
}
