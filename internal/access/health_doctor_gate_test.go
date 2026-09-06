package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// TestHealthDoctorRoutes_requireAdminRole walks the REAL route table.
//
// The Relations & Integrity Doctor's two routes were registered bare:
//
//	api.GET("/health/relations", svc.handleHealthRelations)
//	api.POST("/health/fix/:checkId", svc.handleHealthFix)
//
// while every neighbouring app-publish route carried adminOnly. Both handlers
// deliberately run under orgctx.WithBypassRLS -- the doctor is an install-wide
// diagnostic -- so RLS cannot scope them and the role gate is the only control.
// Unguarded, any authenticated user of any tenant could read an install-wide
// report naming every tenant's apps, hosts, OAuth client ids and Ziti service
// names; run every Safe fix across every tenant with ?heal=safe; or apply one
// named fix, including the two the code itself labels RISKY (tear a service off
// the Ziti controller; consolidate an app, which rewrites another tenant's
// proxy routes and repoints their discovered_paths).
//
// This does not re-register the routes by hand -- that would test a copy. It
// calls RegisterRoutes on a stub service, exactly as test/openapi's spec
// coverage does, and issues real requests through the resulting engine. A
// non-admin must be stopped at 403 by the gate; an admin must get PAST it,
// which on a stub service means 503 from the handler's own
// `healthEngine == nil` guard. A missing gate shows up as the non-admin case
// reaching 503 too.
func TestHealthDoctorRoutes_requireAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// authMiddleware stands in for the bearer auth the group really carries:
	// it sets the roles claim and nothing else, so the only thing between the
	// request and the handler is the route's own gate.
	rolesAs := func(roles ...string) gin.HandlerFunc {
		return func(c *gin.Context) {
			if len(roles) > 0 {
				c.Set("roles", roles)
			}
			c.Next()
		}
	}

	newEngine := func(auth gin.HandlerFunc) *gin.Engine {
		r := gin.New()
		svc := NewService(&database.PostgresDB{}, &database.RedisClient{},
			&config.Config{Environment: "production"}, zap.NewNop())
		RegisterRoutes(r, svc, auth)
		return r
	}

	for _, route := range []struct {
		method, path, body string
	}{
		{"GET", "/api/v1/access/health/relations", ""},
		{"GET", "/api/v1/access/health/relations?heal=safe", ""},
		{"POST", "/api/v1/access/health/fix/published-app", `{"subject":"any"}`},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				auth  gin.HandlerFunc
				want  int
				notes string
			}{
				{"plain user is refused", rolesAs("user"), http.StatusForbidden,
					"an unguarded route would reach the handler instead"},
				{"no roles is refused", rolesAs(), http.StatusForbidden,
					"a caller with no roles claim must fail closed"},
				{"admin gets past the gate", rolesAs("admin"), http.StatusServiceUnavailable,
					"503 is the handler's own nil-healthEngine answer: the gate let it through"},
				{"super_admin gets past the gate", rolesAs("super_admin"), http.StatusServiceUnavailable,
					"503 is the handler's own nil-healthEngine answer: the gate let it through"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var body *strings.Reader
					if route.body != "" {
						body = strings.NewReader(route.body)
					} else {
						body = strings.NewReader("")
					}
					req := httptest.NewRequest(route.method, route.path, body)
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					newEngine(tc.auth).ServeHTTP(w, req)
					if w.Code != tc.want {
						t.Errorf("%s %s as %s = %d, want %d (%s) body=%s",
							route.method, route.path, tc.name, w.Code, tc.want, tc.notes, w.Body.String())
					}
				})
			}
		})
	}
}
