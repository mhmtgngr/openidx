package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/organization"
)

// adminAPIAfterAuth is the chain cmd/admin-api mounts on /api/v1: the bearer is
// authenticated first and the tenant resolver runs after it, with the
// platform-admin predicate and the mandatory cross-org audit hook live. The
// route answers with the organization the request was scoped to. mounts add
// further route tables to the same group, as cmd/admin-api adds the admin
// service's beside the organization API's.
func (h *tokenHarness) adminAPIAfterAuth(mounts ...func(*gin.RouterGroup)) *gin.Engine {
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
	organization.RegisterRoutes(v1, h.orgService)
	for _, mount := range mounts {
		mount(v1)
	}
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
// in A is served; the platform admin -- super_admin held in the default
// organization -- crosses into B, audited where the resolver makes the
// decision, while A's own super_admin is refused like A's admin; and a token
// naming no organization is refused rather than read as the default one.
func TestAnAccessTokenIsBoundToItsOrganization(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("bind-a"), h.seedOrg("bind-b")
	adminA := h.seedUser(orgA.ID, "bind-admin-a", "admin")
	memberA := h.seedUser(orgA.ID, "bind-member-a")
	superA := h.seedUser(orgA.ID, "bind-super-a", "super_admin")
	platform := h.seedUser(middleware.DefaultOrgID, "bind-platform", "super_admin")
	userB := h.seedUser(orgB.ID, "bind-user-b")

	adminToken, superToken := h.accessToken(orgA, adminA), h.accessToken(orgA, superA)
	platformToken := h.accessToken(defaultOrg, platform)
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
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+userB, platformToken, orgB.Slug); w.Code != http.StatusOK {
			t.Errorf("the platform admin, X-Org-Slug B: %d, want 200: %s", w.Code, w.Body.String())
		}
		if w := h.call(h.identityAPI, "/api/v1/identity/users/"+userB, superToken, orgB.Slug); w.Code != http.StatusForbidden {
			t.Errorf("A's super_admin, X-Org-Slug B: %d, want 403: %s", w.Code, w.Body.String())
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
		if code, _ := scopedTo(superToken, orgB.Slug); code != http.StatusForbidden {
			t.Errorf("A's super_admin, X-Org-Slug B: %d, want 403", code)
		}
		if h.crossOrgAudits(orgB.ID) != before {
			t.Error("A's super_admin: a refused crossing wrote a cross-org audit row")
		}
		if code, org := scopedTo(platformToken, orgB.Slug); code != http.StatusOK || org != orgB.ID {
			t.Errorf("the platform admin, X-Org-Slug B: %d scoped to %q, want 200 in B", code, org)
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
		for name, bearer := range map[string]string{"A's admin": adminToken, "A's super_admin": superToken, "the platform admin": platformToken} {
			if w := h.call(h.oauthAPI, "/oauth/userinfo", bearer, orgB.Slug); w.Code != http.StatusUnauthorized {
				t.Errorf("%s, X-Org-Slug B: %d, want 401: %s", name, w.Code, w.Body.String())
			}
		}
		if w := h.call(h.oauthAPI, "/oauth/userinfo", h.withoutOrg(adminToken), orgA.Slug); w.Code != http.StatusUnauthorized {
			t.Errorf("a token naming no organization: %d, want 401", w.Code)
		}
	})
}

// The organization service answers to the platform-admin marker the tenant
// resolver attaches on admin-api. The platform admin -- super_admin held in the
// default organization -- lists every organization, administers any of them
// and crosses into them by X-Org-ID. super_admin held in another organization
// is that organization's role: its holder lists only the organizations they
// belong to, cannot change another one, and X-Org-ID does not move them.
func TestOnlyTheDefaultOrganizationsSuperAdminIsAPlatformAdmin(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("plat-a"), h.seedOrg("plat-b")
	platform := h.seedUser(middleware.DefaultOrgID, "plat-platform", "super_admin")
	superA := h.seedUser(orgA.ID, "plat-super-a", "super_admin")
	if _, err := h.db.Pool.Exec(context.Background(), `
		INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')`,
		orgA.ID, superA); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	platformToken, superToken := h.accessToken(defaultOrg, platform), h.accessToken(orgA, superA)
	api := h.adminAPIAfterAuth()

	send := func(method, path, bearer string, headers map[string]string, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		return w
	}
	listed := func(bearer string) map[string]bool {
		t.Helper()
		w := send(http.MethodGet, "/api/v1/organizations?limit=100", bearer, nil, "")
		if w.Code != http.StatusOK {
			t.Fatalf("list organizations: %d %s", w.Code, w.Body.String())
		}
		var orgs []map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &orgs); err != nil {
			t.Fatalf("list organizations: %v: %s", err, w.Body.String())
		}
		ids := map[string]bool{}
		for _, o := range orgs {
			id, _ := o["id"].(string)
			ids[id] = true
		}
		return ids
	}
	update := func(bearer, orgID string) int {
		t.Helper()
		return send(http.MethodPut, "/api/v1/organizations/"+orgID, bearer, nil,
			`{"name":"renamed by the test","plan":"free","status":"active"}`).Code
	}

	if ids := listed(platformToken); !ids[orgA.ID] || !ids[orgB.ID] || !ids[middleware.DefaultOrgID] {
		t.Errorf("the platform admin's list is missing organizations: %v", ids)
	}
	if ids := listed(superToken); !ids[orgA.ID] || ids[orgB.ID] || ids[middleware.DefaultOrgID] || len(ids) != 1 {
		t.Errorf("A's super_admin listed %v, want only A", ids)
	}

	if code := update(superToken, orgB.ID); code != http.StatusForbidden {
		t.Errorf("A's super_admin updating B: %d, want 403", code)
	}
	if code := update(platformToken, orgB.ID); code != http.StatusOK {
		t.Errorf("the platform admin updating B: %d, want 200", code)
	}

	scopedBy := func(bearer string, headers map[string]string) (int, string) {
		t.Helper()
		w := send(http.MethodGet, "/api/v1/probe", bearer, headers, "")
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		org, _ := body["org_id"].(string)
		return w.Code, org
	}
	before := h.crossOrgAudits(orgB.ID)
	if code, org := scopedBy(superToken, map[string]string{"X-Org-ID": orgB.ID}); code != http.StatusOK || org != orgA.ID {
		t.Errorf("A's super_admin, X-Org-ID B: %d scoped to %q, want 200 in A", code, org)
	}
	if code, _ := scopedBy(superToken, map[string]string{"X-Org-Slug": "default"}); code != http.StatusForbidden {
		t.Errorf("A's super_admin, X-Org-Slug default: %d, want 403", code)
	}
	if h.crossOrgAudits(orgB.ID) != before {
		t.Error("A's super_admin wrote a cross-org audit row")
	}
	if code, org := scopedBy(platformToken, map[string]string{"X-Org-ID": orgB.ID}); code != http.StatusOK || org != orgB.ID {
		t.Errorf("the platform admin, X-Org-ID B: %d scoped to %q, want 200 in B", code, org)
	}
	if got := h.crossOrgAudits(orgB.ID); got != before+1 {
		t.Errorf("cross-org audit rows under B = %d, want %d", got, before+1)
	}
}
