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
// organization and role list, the second over the organization and roles the
// auth middleware bound into the gin context. If they drift, a caller could
// cross organizations through one door and not the other.
func TestIsPlatformAdminAgreesWithSuperAdminPredicate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, org := range []string{middleware.DefaultOrgID, "aaaaaaaa-0000-0000-0000-00000000000a", ""} {
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
			if org != "" {
				c.Set("org_id", org)
			}
			if got, want := middleware.IsPlatformAdmin(org, roles), auth.SuperAdminPredicate(c); got != want {
				t.Errorf("org %q, roles %q: IsPlatformAdmin = %v, auth.SuperAdminPredicate = %v", org, roles, got, want)
			}
		}
	}
}
