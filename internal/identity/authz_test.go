package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// isIdentitySelfService classifies a REGISTERED ROUTE TEMPLATE, not a request
// path — see the function's own comment for what that distinction cost. The
// samples below are therefore templates as RegisterRoutes writes them.
//
// This is a readable sample. The exhaustive version — every registered route,
// classified by driving the real middleware, with a declared reason for each one
// below the admin tier — is authz_surface_test.go.
func TestIsIdentitySelfService(t *testing.T) {
	selfService := []string{
		"/api/v1/identity/users/me",
		"/api/v1/identity/users/me/tokens",
		"/api/v1/identity/users/me/privacy/dsar",
		"/api/v1/identity/mfa/totp/setup",
		"/api/v1/identity/mfa/methods",
		"/api/v1/identity/trusted-browsers",
		"/api/v1/identity/trusted-browsers/:browser_id",
		"/api/v1/identity/risk-assessment",
		"/api/v1/identity/resend-verification",
	}
	for _, p := range selfService {
		assert.Truef(t, isIdentitySelfService(p), "expected %s to be self-service", p)
	}

	adminTemplates := []string{
		"/api/v1/identity/users",
		"/api/v1/identity/users/search",
		"/api/v1/identity/users/:id",
		"/api/v1/identity/users/:id/roles",
		"/api/v1/identity/roles",
		"/api/v1/identity/groups",
		"/api/v1/identity/hardware-tokens",
		"/api/v1/identity/mfa/bypass-codes/:code_id", // revoke — admin, unlike .../verify
		"/api/v1/identity/users/members",             // must NOT be matched by the /users/me rule
	}
	for _, p := range adminTemplates {
		assert.Falsef(t, isIdentitySelfService(p), "expected %s to require admin", p)
	}
}

// requireAdminUnlessSelfService, driven over the SERVICE'S REAL ROUTE TABLE.
//
// The harness matters as much as the assertions. This used to register a single
// catch-all (`r.Any("/*any", ...)`) and drive paths through it, which meant gin
// never had to choose between two routes — and choosing is exactly where the
// gate went wrong: POST /api/v1/identity/users/me/roles is not a registered
// route, so gin backtracks and serves it from /users/:id/roles, the
// administrative role-grant handler, while the path reads as "/users/me/...".
// A catch-all harness cannot see that, and did not.
func TestRequireAdminUnlessSelfService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := authzSurfaceService()

	// The real templates, with the real gate and an inert handler behind it.
	shape := gin.New()
	RegisterRoutes(shape, svc)

	run := func(method, path string, roles []string) int {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("user_id", "11111111-1111-1111-1111-111111111111")
			if roles != nil {
				c.Set("roles", roles)
			}
			c.Next()
		})
		r.Use(svc.requireAdminUnlessSelfService())
		for _, ri := range shape.Routes() {
			r.Handle(ri.Method, ri.Path, func(c *gin.Context) { c.String(http.StatusOK, "ok") })
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}

	// Self-service is allowed for any authenticated user (even with no roles).
	assert.Equal(t, http.StatusOK, run("GET", "/api/v1/identity/users/me", nil))
	assert.Equal(t, http.StatusOK, run("POST", "/api/v1/identity/mfa/totp/setup", []string{"user"}))

	// Administrative routes are blocked for non-admins.
	assert.Equal(t, http.StatusForbidden,
		run("POST", "/api/v1/identity/users/11111111-1111-1111-1111-111111111111/roles", []string{"user"}))
	assert.Equal(t, http.StatusForbidden, run("GET", "/api/v1/identity/users", nil))

	// AND BLOCKED WHEN THE TARGET IS SPELLED "me". Every one of these paths is
	// served by an administrative /users/:id/... handler; naming the target "me"
	// used to make the gate read the request as self-service and wave it through.
	for _, esc := range []struct{ method, path string }{
		{"POST", "/api/v1/identity/users/me/roles"},
		{"GET", "/api/v1/identity/users/me/roles"},
		{"PUT", "/api/v1/identity/users/me/roles"},
		{"DELETE", "/api/v1/identity/users/me/roles/11111111-1111-1111-1111-111111111111"},
		{"GET", "/api/v1/identity/users/me/role-assignments"},
		{"POST", "/api/v1/identity/users/me/set-password"},
		{"POST", "/api/v1/identity/users/me/reset-password"},
		{"POST", "/api/v1/identity/users/me/offboard"},
		{"DELETE", "/api/v1/identity/users/me/bypass-codes"},
		{"DELETE", "/api/v1/identity/users/me"},
		{"DELETE", "/api/v1/identity/mfa/bypass-codes/verify"},
	} {
		assert.Equalf(t, http.StatusForbidden, run(esc.method, esc.path, []string{"user"}),
			"%s %s is served by an administrative route; a non-admin must be refused", esc.method, esc.path)
	}

	// Administrative routes are allowed for admin / super_admin.
	assert.Equal(t, http.StatusOK,
		run("POST", "/api/v1/identity/users/11111111-1111-1111-1111-111111111111/roles", []string{"admin"}))
	assert.Equal(t, http.StatusOK, run("GET", "/api/v1/identity/users", []string{"super_admin"}))
}
