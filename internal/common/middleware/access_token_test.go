package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/jwksverify"
)

// accessTokenKey is generated once; 2048-bit keygen dominates these tests.
var accessTokenKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// idToken signs claims the way the issuer signs an ID token: RS256 under the
// same key and kid as its access tokens, with the library's default "JWT"
// type and no client_id.
func idToken(t *testing.T, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(accessTokenKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// adminClaims is what an administrator's ID token and access token both
// carry: the roles are the point, since they are what an API authorizes on.
func adminClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":    "11111111-1111-1111-1111-111111111111",
		"aud":    "admin-console",
		"roles":  []interface{}{"admin"},
		"org_id": DefaultOrgID,
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	}
}

func probeRoute(t *testing.T, auth gin.HandlerFunc, bearer string) (status int, body map[string]interface{}, user string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin", auth, func(c *gin.Context) {
		user = c.GetString("user_id")
		if _, ok := c.Get("roles"); ok {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusUnauthorized)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body, user
}

// TestAuthRefusesAnIDToken: an administrator's ID token is signed with the
// same key as their access token and carries the same roles, and it is handed
// to every relying party they sign in to. Auth must not accept it as a bearer.
func TestAuthRefusesAnIDToken(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)
	const kid = "id-token-kid"
	jwks := newFlippableJWKSServer(t, kid, &accessTokenKey.PublicKey)

	status, body, user := probeRoute(t, Auth(jwks.srv.URL), idToken(t, kid, adminClaims()))
	if status != http.StatusUnauthorized || user != "" {
		t.Fatalf("ID token: status %d, handler saw user %q; want 401 before the handler", status, user)
	}
	if body["error"] != "invalid token: not an access token" {
		t.Fatalf("ID token: error = %v", body["error"])
	}

	// The same claims as an access token get in, typed or -- for a token
	// minted before the type was stamped -- naming the client it was issued to.
	if status, _, _ := probeRoute(t, Auth(jwks.srv.URL), signRS256(t, accessTokenKey, kid, adminClaims())); status != http.StatusOK {
		t.Fatalf("access token: status %d, want 200", status)
	}
	legacy := adminClaims()
	legacy["client_id"] = "admin-console"
	legacy[APIAccessClaim] = true
	if status, _, _ := probeRoute(t, Auth(jwks.srv.URL), idToken(t, kid, legacy)); status != http.StatusOK {
		t.Fatalf("pre-upgrade access token: status %d, want 200", status)
	}
}

// TestSoftAuthDoesNotBindAnIDToken: SoftAuth never blocks, so its refusal is
// to leave the request unauthenticated, as it does for any token it cannot
// accept.
func TestSoftAuthDoesNotBindAnIDToken(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)
	const kid = "soft-id-token-kid"
	jwks := newFlippableJWKSServer(t, kid, &accessTokenKey.PublicKey)

	status, _, user := probeRoute(t, SoftAuth(jwks.srv.URL), idToken(t, kid, adminClaims()))
	if user != "" || status != http.StatusUnauthorized {
		t.Fatalf("ID token: handler saw user %q and roles (status %d); SoftAuth bound an ID token", user, status)
	}
	if status, _, user := probeRoute(t, SoftAuth(jwks.srv.URL), signRS256(t, accessTokenKey, kid, adminClaims())); status != http.StatusOK || user == "" {
		t.Fatalf("access token: status %d, user %q; want it bound", status, user)
	}
}

// withoutAPIAccess signs claims as the issuer signs the access token of an
// application that may not call OpenIDX's own APIs: typed, bound to its
// organization, and carrying no API-access claim.
func withoutAPIAccess(t *testing.T, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = AccessTokenType
	signed, err := tok.SignedString(accessTokenKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// TestAuthRefusesATokenWithoutAPIAccess: a third-party application an
// administrator signs in to holds an access token carrying the administrator's
// roles. Auth accepts an access token only from an application allowed to
// call OpenIDX's APIs, SoftAuth leaves the request unauthenticated, and an API
// key, which is no application's token, is unaffected.
func TestAuthRefusesATokenWithoutAPIAccess(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)
	const kid = "api-access-kid"
	jwks := newFlippableJWKSServer(t, kid, &accessTokenKey.PublicKey)
	thirdParty := withoutAPIAccess(t, kid, adminClaims())

	status, body, user := probeRoute(t, Auth(jwks.srv.URL), thirdParty)
	if status != http.StatusUnauthorized || user != "" {
		t.Fatalf("third-party token: status %d, handler saw user %q; want 401 before the handler", status, user)
	}
	if body["error"] != "invalid token: this application may not call the OpenIDX API" {
		t.Fatalf("third-party token: error = %v", body["error"])
	}
	if status, _, user := probeRoute(t, SoftAuth(jwks.srv.URL), thirdParty); user != "" || status != http.StatusUnauthorized {
		t.Fatalf("SoftAuth bound a third-party token: status %d, user %q", status, user)
	}

	if status, _, _ := probeRoute(t, Auth(jwks.srv.URL), signRS256(t, accessTokenKey, kid, adminClaims())); status != http.StatusOK {
		t.Fatalf("the console's token: status %d, want 200", status)
	}
	if status, _, _ := probeRoute(t, AuthWithAPIKey(jwks.srv.URL, orgKeys{}), "oidx_key"); status != http.StatusOK {
		t.Fatalf("an API key: status %d, want 200", status)
	}
}
