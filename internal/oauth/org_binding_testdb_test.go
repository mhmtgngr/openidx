package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// adminAPIAfterAuth is the chain cmd/admin-api mounts on /api/v1: the bearer is
// authenticated first and the tenant resolver runs after it, with the
// platform-admin predicate and the mandatory cross-org audit hook live. The
// route answers with the organization the request was scoped to.
func (h *tokenHarness) adminAPIAfterAuth() *gin.Engine {
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthWithAPIKey(h.jwksURL, nil))
	v1.Use(middleware.TenantResolver(h.orgs, middleware.TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           middleware.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
		OnPlatformCrossOrg:     audit.CrossOrgAuditor(h.db.Pool, zap.NewNop()),
	}))
	v1.GET("/probe", middleware.RequireRoles("admin", "super_admin"), func(c *gin.Context) {
		org, _ := orgctx.From(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"org_id": org.ID})
	})
	return r
}

func (h *tokenHarness) seedOrg(slug string) orgctx.Org {
	h.t.Helper()
	org := orgctx.Org{Slug: slug + "-" + h.suffix}
	if err := h.db.Pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, status) VALUES ($1, $1, 'active') RETURNING id::text`,
		org.Slug).Scan(&org.ID); err != nil {
		h.t.Fatalf("seed organization %s: %v", slug, err)
	}
	return org
}

func (h *tokenHarness) crossOrgAudits(orgID string) int {
	h.t.Helper()
	var n int
	if err := h.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE event_type = 'platform_admin_cross_org_access' AND org_id = $1::uuid`,
		orgID).Scan(&n); err != nil {
		h.t.Fatalf("count cross-org audits: %v", err)
	}
	return n
}

// withoutOrg re-signs an access token's claims with no org_id, the way the
// issuer minted every access token before the claim existed: the library's
// default "JWT" type and a client_id.
func (h *tokenHarness) withoutOrg(accessToken string) string {
	h.t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		h.t.Fatalf("parse: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	delete(claims, middleware.OrgIDClaim)
	kid, key := h.issuer.signingKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		h.t.Fatalf("sign: %v", err)
	}
	return signed
}

// An access token is bound to the organization it was minted in. An
// administrator of A who names B in X-Org-Slug is refused at every validator,
// whichever side of authentication the tenant resolver runs on; the same token
// in A is served; a platform admin of A crosses into B, audited where the
// resolver makes the decision; and a token naming no organization is refused
// rather than read as the default one.
func TestAnAccessTokenIsBoundToItsOrganization(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("bind-a"), h.seedOrg("bind-b")
	adminA := h.seedUser(orgA.ID, "bind-admin-a", "admin")
	memberA := h.seedUser(orgA.ID, "bind-member-a")
	superA := h.seedUser(orgA.ID, "bind-super-a", "super_admin")
	userB := h.seedUser(orgB.ID, "bind-user-b")

	adminToken, superToken := h.accessToken(orgA, adminA), h.accessToken(orgA, superA)
	if bound := header(t, adminToken); bound["typ"] != middleware.AccessTokenType {
		t.Fatalf("typ = %v", bound["typ"])
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(adminToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Claims.(jwt.MapClaims)[middleware.OrgIDClaim]; got != orgA.ID {
		t.Fatalf("GenerateJWT org_id = %v, want the minting organization %s", got, orgA.ID)
	}

	t.Run("identity API, resolver before auth", func(t *testing.T) {
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+userB, adminToken, orgB.Slug); w.Code != http.StatusForbidden {
			t.Errorf("A's admin, X-Org-Slug B: %d, want 403: %s", w.Code, w.Body.String())
		}
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+memberA, adminToken, orgA.Slug); w.Code != http.StatusOK {
			t.Errorf("A's admin, X-Org-Slug A: %d, want 200: %s", w.Code, w.Body.String())
		}
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+memberA, adminToken, ""); w.Code != http.StatusForbidden {
			t.Errorf("A's admin, no slug (default-org fallback): %d, want 403: %s", w.Code, w.Body.String())
		}
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+userB, superToken, orgB.Slug); w.Code != http.StatusOK {
			t.Errorf("A's platform admin, X-Org-Slug B: %d, want 200: %s", w.Code, w.Body.String())
		}
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+memberA, h.withoutOrg(adminToken), orgA.Slug); w.Code != http.StatusUnauthorized {
			t.Errorf("a token naming no organization: %d, want 401: %s", w.Code, w.Body.String())
		}
	})

	t.Run("shared middleware, resolver before auth", func(t *testing.T) {
		if w := h.call(h.adminAPI, "/api/v1/admin/probe", adminToken, orgB.Slug); w.Code != http.StatusForbidden {
			t.Errorf("A's admin, X-Org-Slug B: %d, want 403", w.Code)
		}
		if w := h.call(h.adminAPI, "/api/v1/admin/probe", adminToken, orgA.Slug); w.Code != http.StatusOK {
			t.Errorf("A's admin, X-Org-Slug A: %d, want 200", w.Code)
		}
		if w := h.call(h.adminAPI, "/api/v1/admin/probe", h.withoutOrg(adminToken), ""); w.Code != http.StatusUnauthorized {
			t.Errorf("a token naming no organization, default org: %d, want 401", w.Code)
		}
	})

	t.Run("admin-api, resolver after auth", func(t *testing.T) {
		api := h.adminAPIAfterAuth()
		scopedTo := func(bearer, slug string) (int, string) {
			w := h.call(api, "/api/v1/probe", bearer, slug)
			var body map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			org, _ := body["org_id"].(string)
			return w.Code, org
		}

		before := h.crossOrgAudits(orgB.ID)
		if code, _ := scopedTo(adminToken, orgB.Slug); code != http.StatusForbidden {
			t.Errorf("A's admin, X-Org-Slug B: %d, want 403", code)
		}
		if h.crossOrgAudits(orgB.ID) != before {
			t.Error("a refused crossing wrote a cross-org audit row")
		}
		if code, org := scopedTo(adminToken, orgA.Slug); code != http.StatusOK || org != orgA.ID {
			t.Errorf("A's admin, X-Org-Slug A: %d scoped to %q, want 200 in A", code, org)
		}
		if code, org := scopedTo(adminToken, ""); code != http.StatusOK || org != orgA.ID {
			t.Errorf("A's admin, no slug: %d scoped to %q, want 200 in A (the token's organization)", code, org)
		}
		if code, org := scopedTo(superToken, orgB.Slug); code != http.StatusOK || org != orgB.ID {
			t.Errorf("A's platform admin, X-Org-Slug B: %d scoped to %q, want 200 in B", code, org)
		}
		if got := h.crossOrgAudits(orgB.ID); got != before+1 {
			t.Errorf("cross-org audit rows under B = %d, want %d: the platform admin's crossing was not audited", got, before+1)
		}
		if code, _ := scopedTo(h.withoutOrg(adminToken), ""); code != http.StatusUnauthorized {
			t.Errorf("a token naming no organization: %d, want 401", code)
		}
	})

	t.Run("userinfo", func(t *testing.T) {
		if w := h.call(h.oauthAPI, "/oauth/userinfo", adminToken, orgA.Slug); w.Code != http.StatusOK {
			t.Errorf("A's admin in A: %d, want 200: %s", w.Code, w.Body.String())
		}
		for name, bearer := range map[string]string{"A's admin": adminToken, "A's platform admin": superToken} {
			if w := h.call(h.oauthAPI, "/oauth/userinfo", bearer, orgB.Slug); w.Code != http.StatusUnauthorized {
				t.Errorf("%s, X-Org-Slug B: %d, want 401: %s", name, w.Code, w.Body.String())
			}
		}
		if w := h.call(h.oauthAPI, "/oauth/userinfo", h.withoutOrg(adminToken), orgA.Slug); w.Code != http.StatusUnauthorized {
			t.Errorf("a token naming no organization: %d, want 401", w.Code)
		}
	})
}
