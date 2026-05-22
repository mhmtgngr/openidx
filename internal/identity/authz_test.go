package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestIsIdentitySelfService(t *testing.T) {
	selfService := []string{
		"/api/v1/identity/users/me",
		"/api/v1/identity/users/me/tokens",
		"/api/v1/identity/users/me/privacy/dsar",
		"/api/v1/identity/mfa/totp/setup",
		"/api/v1/identity/mfa/methods",
		"/api/v1/identity/trusted-browsers",
		"/api/v1/identity/trusted-browsers/abc",
		"/api/v1/identity/risk-assessment",
		"/api/v1/identity/resend-verification",
	}
	for _, p := range selfService {
		assert.Truef(t, isIdentitySelfService(p), "expected %s to be self-service", p)
	}

	adminPaths := []string{
		"/api/v1/identity/users",
		"/api/v1/identity/users/search",
		"/api/v1/identity/users/123",
		"/api/v1/identity/users/123/roles",
		"/api/v1/identity/roles",
		"/api/v1/identity/groups",
		"/api/v1/identity/hardware-tokens",
		"/api/v1/identity/users/members", // must NOT be matched by the /users/me rule
	}
	for _, p := range adminPaths {
		assert.Falsef(t, isIdentitySelfService(p), "expected %s to require admin", p)
	}
}

func TestRequireAdminUnlessSelfService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{}

	run := func(path string, roles []string) int {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if roles != nil {
				c.Set("roles", roles)
			}
			c.Next()
		})
		r.Use(svc.requireAdminUnlessSelfService())
		r.Any("/*any", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, nil)
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Self-service is allowed for any authenticated user (even with no roles).
	assert.Equal(t, http.StatusOK, run("/api/v1/identity/users/me", nil))
	assert.Equal(t, http.StatusOK, run("/api/v1/identity/mfa/totp/setup", []string{"user"}))

	// Administrative routes are blocked for non-admins — including the
	// privilege-escalation path POST /users/:id/roles.
	assert.Equal(t, http.StatusForbidden, run("/api/v1/identity/users/123/roles", []string{"user"}))
	assert.Equal(t, http.StatusForbidden, run("/api/v1/identity/users", nil))

	// Administrative routes are allowed for admin / super_admin.
	assert.Equal(t, http.StatusOK, run("/api/v1/identity/users/123/roles", []string{"admin"}))
	assert.Equal(t, http.StatusOK, run("/api/v1/identity/users", []string{"super_admin"}))
}
