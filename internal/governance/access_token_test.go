package governance

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// An administrator's ID token verifies against the key that signs their access
// token and carries the same roles. openIDXAuthMiddleware must refuse it; the
// same claims typed as an access token are the control.
func TestGovernanceRefusesAnIDToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://issuer.test"
	s := &Service{
		logger:          zap.NewNop(),
		config:          &config.Config{OAuthIssuer: issuer},
		jwksCachedKey:   &key.PublicKey,
		jwksCacheExpiry: time.Now().Add(time.Hour),
	}
	router := gin.New()
	router.GET("/api/v1/governance/policies", s.openIDXAuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	sign := func(typ string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "u1", "iss": issuer, "aud": "admin-console", "roles": []interface{}{"admin"},
			"org_id": middleware.DefaultOrgID, middleware.APIAccessClaim: true,
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		if typ != "" {
			tok.Header["typ"] = typ
		}
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	call := func(bearer string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/governance/policies", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := call(sign("")); code != http.StatusUnauthorized {
		t.Fatalf("an admin's ID token answered %d, want 401", code)
	}
	if code := call(sign(middleware.AccessTokenType)); code != http.StatusOK {
		t.Fatalf("the same claims as an access token answered %d, want 200", code)
	}
}

// A token's roles hold in the organization it was minted in. With the tenant
// resolver mounted ahead of this middleware, as the service mounts it, a token
// of another organization is refused unless it is a platform admin's, and a
// token naming no organization is refused rather than read as the default one.
func TestGovernanceBindsATokenToItsOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		issuer = "https://issuer.test"
		orgA   = "aaaaaaaa-0000-0000-0000-00000000000a"
		orgB   = "bbbbbbbb-0000-0000-0000-00000000000b"
	)
	s := &Service{
		logger:          zap.NewNop(),
		config:          &config.Config{OAuthIssuer: issuer},
		jwksCachedKey:   &key.PublicKey,
		jwksCacheExpiry: time.Now().Add(time.Hour),
	}
	call := func(resolved, tokenOrg, role string) int {
		t.Helper()
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: resolved}))
			c.Next()
		})
		router.GET("/api/v1/governance/policies", s.openIDXAuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })
		claims := jwt.MapClaims{
			"sub": "u1", "iss": issuer, "client_id": "admin-console", "roles": []interface{}{role},
			middleware.APIAccessClaim: true, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if tokenOrg != "" {
			claims[middleware.OrgIDClaim] = tokenOrg
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["typ"] = middleware.AccessTokenType
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/governance/policies", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	for _, tc := range []struct {
		name                     string
		resolved, tokenOrg, role string
		want                     int
	}{
		{"its own organization", orgA, orgA, "admin", http.StatusOK},
		{"another organization", orgB, orgA, "admin", http.StatusForbidden},
		{"a platform admin in another organization", orgB, orgA, "super_admin", http.StatusOK},
		{"no organization", middleware.DefaultOrgID, "", "admin", http.StatusUnauthorized},
	} {
		if got := call(tc.resolved, tc.tokenOrg, tc.role); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}

// An administrator who signs in to a third-party application hands it an
// access token carrying their roles. openIDXAuthMiddleware accepts the access
// token of an application allowed to call OpenIDX's APIs and refuses the same
// token without that claim.
func TestGovernanceRefusesATokenWithoutAPIAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://issuer.test"
	s := &Service{
		logger:          zap.NewNop(),
		config:          &config.Config{OAuthIssuer: issuer},
		jwksCachedKey:   &key.PublicKey,
		jwksCacheExpiry: time.Now().Add(time.Hour),
	}
	router := gin.New()
	router.GET("/api/v1/governance/policies", s.openIDXAuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	call := func(apiAccess bool) (int, string) {
		t.Helper()
		claims := jwt.MapClaims{
			"sub": "u1", "iss": issuer, "client_id": "third-party", "roles": []interface{}{"admin"},
			"org_id": middleware.DefaultOrgID, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if apiAccess {
			claims[middleware.APIAccessClaim] = true
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["typ"] = middleware.AccessTokenType
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/governance/policies", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	if code, body := call(false); code != http.StatusUnauthorized || !strings.Contains(body, "may not call the OpenIDX API") {
		t.Fatalf("a token without API access answered %d %s, want 401 naming the reason", code, body)
	}
	if code, _ := call(true); code != http.StatusOK {
		t.Fatalf("the same token with API access answered %d, want 200", code)
	}
}
