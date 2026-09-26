package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/middleware"
)

// The platform-admin exception to token binding and the tenant resolver's
// platform-admin predicate are one rule stated twice: the first over a token's
// role list, the second over the roles the auth middleware bound into the gin
// context. If they drift, a caller could cross organizations through one door
// and not the other.
func TestIsPlatformAdminAgreesWithSuperAdminPredicate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, roles := range [][]string{
		nil,
		{},
		{"admin"},
		{"user", "auditor"},
		{"super_admin"},
		{"admin", "super_admin"},
		{"Super_Admin"},
		{"super_admin "},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if roles != nil {
			c.Set("roles", roles)
		}
		if got, want := middleware.IsPlatformAdmin(roles), auth.SuperAdminPredicate(c); got != want {
			t.Errorf("roles %q: IsPlatformAdmin = %v, auth.SuperAdminPredicate = %v", roles, got, want)
		}
	}
}
