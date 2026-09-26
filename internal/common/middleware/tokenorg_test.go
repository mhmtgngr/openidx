package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/jwksverify"
	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	orgA = "aaaaaaaa-0000-0000-0000-00000000000a"
	orgB = "bbbbbbbb-0000-0000-0000-00000000000b"
)

// resolvedTo stands in for TenantResolver mounted ahead of authentication, as
// every service but admin-api mounts it: X-Org-Slug, or the default-org
// fallback, has already decided the organization.
func resolvedTo(orgID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Next()
	}
}

type orgProbe struct {
	status  int
	body    map[string]interface{}
	reached bool
	orgID   string
}

func probeOrg(t *testing.T, chain []gin.HandlerFunc, bearer string) orgProbe {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var p orgProbe
	r := gin.New()
	r.GET("/api", append(chain, func(c *gin.Context) {
		p.reached = true
		p.orgID = c.GetString("org_id")
		c.Status(http.StatusOK)
	})...)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	p.status = w.Code
	_ = json.Unmarshal(w.Body.Bytes(), &p.body)
	return p
}

// tokenIn signs an access token minted in orgID holding roles; an empty orgID
// leaves the claim out, as every token minted before it existed does.
func tokenIn(t *testing.T, kid, orgID string, roles ...string) string {
	t.Helper()
	roleClaim := make([]interface{}, 0, len(roles))
	for _, r := range roles {
		roleClaim = append(roleClaim, r)
	}
	claims := jwt.MapClaims{
		"sub":          "11111111-1111-1111-1111-111111111111",
		"roles":        roleClaim,
		APIAccessClaim: true,
		"exp":          float64(time.Now().Add(time.Hour).Unix()),
	}
	if orgID != "" {
		claims[OrgIDClaim] = orgID
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = AccessTokenType
	signed, err := tok.SignedString(accessTokenKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// TestAuthBindsATokenToItsOrganization: the roles in a token are its holder's
// roles in the organization it was minted in. Auth serves it there, refuses it
// in any other organization the request resolved to, and refuses a token that
// names no organization instead of reading it as the default one.
func TestAuthBindsATokenToItsOrganization(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)
	const kid = "token-org-kid"
	jwks := newFlippableJWKSServer(t, kid, &accessTokenKey.PublicKey)
	auth := Auth(jwks.srv.URL)

	if p := probeOrg(t, []gin.HandlerFunc{resolvedTo(orgA), auth}, tokenIn(t, kid, orgA, "admin")); p.status != http.StatusOK || p.orgID != orgA {
		t.Fatalf("own organization: status %d, org_id %q; want 200 and %s", p.status, p.orgID, orgA)
	}

	p := probeOrg(t, []gin.HandlerFunc{resolvedTo(orgB), auth}, tokenIn(t, kid, orgA, "admin"))
	if p.status != http.StatusForbidden || p.reached {
		t.Fatalf("another organization: status %d, handler reached %v; want 403 before the handler", p.status, p.reached)
	}
	if p.body["error"] != "token is not valid for this organization" {
		t.Fatalf("another organization: error = %v", p.body["error"])
	}

	if p := probeOrg(t, []gin.HandlerFunc{resolvedTo(orgB), auth}, tokenIn(t, kid, orgA, "super_admin")); p.status != http.StatusOK {
		t.Fatalf("a platform admin in another organization: status %d, want 200", p.status)
	}

	// No organization resolved yet: cmd/admin-api, where the resolver runs
	// after this middleware and compares for itself.
	if p := probeOrg(t, []gin.HandlerFunc{auth}, tokenIn(t, kid, orgA, "admin")); p.status != http.StatusOK || p.orgID != orgA {
		t.Fatalf("resolver after auth: status %d, org_id %q; want 200 and %s", p.status, p.orgID, orgA)
	}

	for _, resolved := range []string{DefaultOrgID, orgB} {
		p := probeOrg(t, []gin.HandlerFunc{resolvedTo(resolved), auth}, tokenIn(t, kid, "", "admin"))
		if p.status != http.StatusUnauthorized || p.reached {
			t.Fatalf("no organization, request in %s: status %d; want 401 before the handler", resolved, p.status)
		}
		if p.body["error"] != "invalid token: token has no organization; sign in again" {
			t.Fatalf("no organization: error = %v", p.body["error"])
		}
	}
}

// TestSoftAuthBindsATokenToItsOrganization: SoftAuth fronts routes that act on
// the resolved organization too. A token of another organization is refused as
// Auth refuses it; a token naming none is one SoftAuth cannot accept, so the
// request goes on unauthenticated.
func TestSoftAuthBindsATokenToItsOrganization(t *testing.T) {
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.ResetCache)
	const kid = "soft-token-org-kid"
	jwks := newFlippableJWKSServer(t, kid, &accessTokenKey.PublicKey)
	soft := SoftAuth(jwks.srv.URL)

	if p := probeOrg(t, []gin.HandlerFunc{resolvedTo(orgA), soft}, tokenIn(t, kid, orgA, "admin")); p.status != http.StatusOK || p.orgID != orgA {
		t.Fatalf("own organization: status %d, org_id %q", p.status, p.orgID)
	}
	if p := probeOrg(t, []gin.HandlerFunc{resolvedTo(orgB), soft}, tokenIn(t, kid, orgA, "admin")); p.status != http.StatusForbidden || p.reached {
		t.Fatalf("another organization: status %d, reached %v; want 403", p.status, p.reached)
	}
	if p := probeOrg(t, []gin.HandlerFunc{resolvedTo(DefaultOrgID), soft}, tokenIn(t, kid, "", "admin")); p.status != http.StatusOK || p.orgID != "" {
		t.Fatalf("no organization: status %d, org_id %q; want the request unauthenticated", p.status, p.orgID)
	}
}

type orgKeys struct{ org string }

func (k orgKeys) ValidateAPIKey(context.Context, string) (*APIKeyInfo, error) {
	return &APIKeyInfo{KeyID: "k1", ServiceAccountID: "sa1", OrgID: k.org}, nil
}

// TestAnAPIKeyIsBoundToItsOrganization: an API key belongs to one organization,
// the default one when it records none, and is refused in any other.
func TestAnAPIKeyIsBoundToItsOrganization(t *testing.T) {
	cases := []struct {
		name     string
		keyOrg   string
		resolved string
		want     int
	}{
		{"its own organization", orgA, orgA, http.StatusOK},
		{"another organization", orgA, orgB, http.StatusForbidden},
		{"a key recording no organization, in the default one", "", DefaultOrgID, http.StatusOK},
		{"a key recording no organization, elsewhere", "", orgB, http.StatusForbidden},
	}
	for _, tc := range cases {
		p := probeOrg(t, []gin.HandlerFunc{resolvedTo(tc.resolved), AuthWithAPIKey("http://127.0.0.1:0/jwks", orgKeys{tc.keyOrg})}, "oidx_key")
		if p.status != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, p.status, tc.want)
		}
	}
}

func TestCheckTokenOrg(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgB}))

	if _, err := CheckTokenOrg(c, map[string]interface{}{"sub": "u"}); !errors.Is(err, ErrNoOrganization) {
		t.Errorf("no org: %v", err)
	}
	if _, err := CheckTokenOrg(c, map[string]interface{}{OrgIDClaim: orgA, "roles": []interface{}{"admin"}}); !errors.Is(err, ErrWrongOrganization) {
		t.Errorf("another org: %v", err)
	}
	if org, err := CheckTokenOrg(c, map[string]interface{}{OrgIDClaim: orgA, "roles": []interface{}{"super_admin"}}); err != nil || org != orgA {
		t.Errorf("platform admin: %q, %v", org, err)
	}
	if org, err := CheckTokenOrg(c, map[string]interface{}{OrgIDClaim: orgB}); err != nil || org != orgB {
		t.Errorf("own org: %q, %v", org, err)
	}
}
