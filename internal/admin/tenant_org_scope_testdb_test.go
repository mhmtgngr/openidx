package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/organization"
)

// THE TENANT ROUTES STAY IN THE CALLER'S ORGANIZATION.
//
// tenant_branding, tenant_settings and tenant_domains span the install, outside
// the RLS belt, and /api/v1/tenants/:orgId takes the organization from the
// path. Driven through RegisterRoutes -- the route table cmd/admin-api serves --
// behind the tenant resolver as cmd/admin-api mounts it, after authentication
// and with the platform-admin predicate, and a stand-in for the validator that
// binds what the validator binds: the caller's user id and roles and the
// organization the credential belongs to. Everything a request acts on is
// seeded for that request and read back around it:
//
//   - A's admin naming B is answered 404 on every route, reads nothing of B's
//     and changes nothing of it; naming A, the same admin reads and writes A's;
//   - B's admin, and the platform admin -- super_admin held in the default
//     organization -- read and write B's;
//   - the tenant switch answers A's admin 404 for B, and 200 for A and for an
//     organization organization_members lists them in; the platform admin
//     switches to B.
func TestTenantRoutesStayInTheCallersOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	scalar := func(query string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", query, err)
		}
		return v
	}
	newOrg := func(name string) string {
		return scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, name+"-"+suffix)
	}
	newUser := func(org, name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
			RETURNING id::text`, org, name+"-"+suffix)
	}
	orgA, orgB, orgC := newOrg("tenant-a"), newOrg("tenant-b"), newOrg("tenant-c")
	adminA, adminB := newUser(orgA, "tenant-admin-a"), newUser(orgB, "tenant-admin-b")
	platform := newUser(middleware.DefaultOrgID, "tenant-platform")
	// A's admin also belongs to C, as organization_members records it.
	scalar(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'admin') RETURNING id::text`, orgC, adminA)

	svc := NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	lookup := organization.NewOrgLookup(organization.NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop()))

	type caller struct {
		name, user, org string
		roles           []string
		target          string // the organization the path names
		admitted        bool
	}
	callers := []caller{
		{"A's admin, naming B", adminA, orgA, []string{"admin"}, orgB, false},
		{"A's admin, naming A", adminA, orgA, []string{"admin"}, orgA, true},
		{"B's admin, naming B", adminB, orgB, []string{"admin"}, orgB, true},
		{"the platform admin, naming B", platform, middleware.DefaultOrgID, []string{"super_admin"}, orgB, true},
	}
	engineFor := func(cl caller) *gin.Engine {
		r := gin.New()
		v1 := r.Group("/api/v1")
		v1.Use(func(c *gin.Context) {
			c.Set("user_id", cl.user)
			c.Set("roles", cl.roles)
			c.Set("org_id", cl.org)
			c.Next()
		})
		v1.Use(middleware.TenantResolver(lookup, middleware.TenantResolverConfig{
			DefaultOrgFallback:     true,
			DefaultOrgID:           middleware.DefaultOrgID,
			PlatformAdminPredicate: auth.SuperAdminPredicate,
		}))
		RegisterRoutes(v1, svc)
		return r
	}

	// What each request acts on, seeded in the organization the path names.
	tag := func(kind string, n int) string { return fmt.Sprintf("%s-%d-%s", kind, n, suffix) }
	seedBranding := func(org string, n int) string {
		title := tag("title", n)
		scalar(`INSERT INTO tenant_branding (org_id, login_page_title) VALUES ($1::uuid, $2)
			ON CONFLICT (org_id) DO UPDATE SET login_page_title = EXCLUDED.login_page_title RETURNING id::text`, org, title)
		return title
	}
	seedSettings := func(org string, n int) string {
		marker := tag("setting", n)
		scalar(`INSERT INTO tenant_settings (org_id, category, settings) VALUES ($1::uuid, 'security', jsonb_build_object('marker', $2::text))
			ON CONFLICT (org_id, category) DO UPDATE SET settings = EXCLUDED.settings RETURNING id::text`, org, marker)
		return marker
	}
	seedDomain := func(org string, n int) (id, domain string) {
		domain = tag("domain", n) + ".example.test"
		id = scalar(`INSERT INTO tenant_domains (org_id, domain, verification_token) VALUES ($1::uuid, $2, 'seeded-token') RETURNING id::text`, org, domain)
		return id, domain
	}
	read := func(query, arg string) func() string {
		return func() string { return scalar(query, arg) }
	}

	type route struct {
		method, route string
		call          func(org string, n int) (path, body, marker string, state func() string)
	}
	routes := []route{
		{http.MethodGet, "/tenants/:orgId/branding", func(org string, n int) (string, string, string, func() string) {
			return "/api/v1/tenants/" + org + "/branding", "", seedBranding(org, n), nil
		}},
		{http.MethodPut, "/tenants/:orgId/branding", func(org string, n int) (string, string, string, func() string) {
			seedBranding(org, n)
			return "/api/v1/tenants/" + org + "/branding", `{"login_page_title":"` + tag("rewritten", n) + `","powered_by_visible":true}`,
				"", read(`SELECT login_page_title FROM tenant_branding WHERE org_id = $1::uuid`, org)
		}},
		{http.MethodGet, "/tenants/:orgId/settings", func(org string, n int) (string, string, string, func() string) {
			return "/api/v1/tenants/" + org + "/settings", "", seedSettings(org, n), nil
		}},
		{http.MethodPut, "/tenants/:orgId/settings", func(org string, n int) (string, string, string, func() string) {
			seedSettings(org, n)
			return "/api/v1/tenants/" + org + "/settings", `{"category":"security","settings":{"marker":"` + tag("rewritten", n) + `"}}`,
				"", read(`SELECT settings::text FROM tenant_settings WHERE org_id = $1::uuid AND category = 'security'`, org)
		}},
		{http.MethodGet, "/tenants/:orgId/domains", func(org string, n int) (string, string, string, func() string) {
			_, domain := seedDomain(org, n)
			return "/api/v1/tenants/" + org + "/domains", "", domain, nil
		}},
		{http.MethodPost, "/tenants/:orgId/domains", func(org string, n int) (string, string, string, func() string) {
			domain := tag("added", n) + ".example.test"
			return "/api/v1/tenants/" + org + "/domains", `{"domain":"` + domain + `","domain_type":"custom"}`,
				"", read(`SELECT COUNT(*)::text FROM tenant_domains WHERE domain = $1`, domain)
		}},
		{http.MethodDelete, "/tenants/:orgId/domains/:domainId", func(org string, n int) (string, string, string, func() string) {
			id, _ := seedDomain(org, n)
			return "/api/v1/tenants/" + org + "/domains/" + id, "",
				"", read(`SELECT COUNT(*)::text FROM tenant_domains WHERE id = $1::uuid`, id)
		}},
		{http.MethodPost, "/tenants/:orgId/domains/:domainId/verify", func(org string, n int) (string, string, string, func() string) {
			id, _ := seedDomain(org, n)
			return "/api/v1/tenants/" + org + "/domains/" + id + "/verify", `{"token":"seeded-token"}`,
				"", read(`SELECT COALESCE(verified, false)::text FROM tenant_domains WHERE id = $1::uuid`, id)
		}},
	}

	n := 0
	for _, rt := range routes {
		rt := rt
		t.Run(rt.method+" "+rt.route, func(t *testing.T) {
			for _, cl := range callers {
				n++
				path, body, marker, state := rt.call(cl.target, n)
				var before string
				if state != nil {
					before = state()
				}
				req := httptest.NewRequest(rt.method, path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				engineFor(cl).ServeHTTP(w, req)
				var after string
				if state != nil {
					after = state()
				}
				shows := marker != "" && strings.Contains(w.Body.String(), marker)

				if cl.admitted {
					if w.Code < 200 || w.Code > 299 {
						t.Errorf("%s: status %d (%s), want 2xx", cl.name, w.Code, w.Body.String())
					}
					if marker != "" && !shows {
						t.Errorf("%s: the answer does not carry %s: %s", cl.name, marker, w.Body.String())
					}
					if state != nil && before == after {
						t.Errorf("%s was admitted (%d) but nothing changed: %s", cl.name, w.Code, after)
					}
					continue
				}
				if w.Code != http.StatusNotFound {
					t.Errorf("%s: status %d (%s), want 404", cl.name, w.Code, w.Body.String())
				}
				if shows {
					t.Errorf("%s: the answer carries the other organization's %s: %s", cl.name, marker, w.Body.String())
				}
				if before != after {
					t.Errorf("%s changed the other organization's state:\n  before %s\n  after  %s", cl.name, before, after)
				}
			}
		})
	}

	t.Run("POST /tenants/switch", func(t *testing.T) {
		nameOf := func(org string) string { return scalar(`SELECT name FROM organizations WHERE id = $1::uuid`, org) }
		for _, tc := range []struct {
			who    caller
			target string
			want   int
		}{
			{callers[0], orgB, http.StatusNotFound},
			{callers[0], orgA, http.StatusOK},
			{callers[0], orgC, http.StatusOK},
			{callers[3], orgB, http.StatusOK},
		} {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/switch", strings.NewReader(`{"org_id":"`+tc.target+`"}`))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			engineFor(tc.who).ServeHTTP(w, req)
			shows := strings.Contains(w.Body.String(), nameOf(tc.target))
			if w.Code != tc.want || shows != (tc.want == http.StatusOK) {
				t.Errorf("%s switching to %s: %d %s, want %d", tc.who.user, nameOf(tc.target), w.Code, w.Body.String(), tc.want)
			}
		}
	})
}
