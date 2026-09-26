package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/middleware"
)

// TestSuperAdminPredicate locks in the cross-org privilege gate wired into every
// service's tenant resolver: only super_admin held in the install's default
// organization is treated as a platform admin (may cross org boundaries via
// X-Org-ID and X-Org-Slug); everything else -- super_admin held in another
// organization, a credential naming no organization, a missing or malformed
// roles claim -- must be denied.
func TestSuperAdminPredicate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	inOrg := func(org string, roles ...string) func(*gin.Context) {
		return func(c *gin.Context) {
			SetRoles(c, roles)
			c.Set("org_id", org)
		}
	}
	const otherOrg = "aaaaaaaa-0000-0000-0000-00000000000a"
	cases := []struct {
		name  string
		setup func(*gin.Context)
		want  bool
	}{
		{"super_admin only", inOrg(middleware.DefaultOrgID, string(RoleSuperAdmin)), true},
		{"super_admin among others", inOrg(middleware.DefaultOrgID, "admin", string(RoleSuperAdmin)), true},
		{"super_admin of another organization", inOrg(otherOrg, string(RoleSuperAdmin)), false},
		{"super_admin naming no organization", func(c *gin.Context) { SetRoles(c, []string{string(RoleSuperAdmin)}) }, false},
		{"non-super roles only", inOrg(middleware.DefaultOrgID, "admin", "auditor"), false},
		{"no roles set", func(c *gin.Context) {}, false},
		{"roles wrong type", func(c *gin.Context) { c.Set(ContextKeyRoles, "not-a-slice") }, false},
		{"empty roles slice", inOrg(middleware.DefaultOrgID), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tc.setup(c)
			if got := SuperAdminPredicate(c); got != tc.want {
				t.Errorf("SuperAdminPredicate = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsSuperAdminInContext checks the (bool,error) form both ways.
func TestIsSuperAdminInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetRoles(c, []string{string(RoleSuperAdmin)})
	if ok, err := IsSuperAdminInContext(c); err != nil || !ok {
		t.Fatalf("super_admin: got (%v,%v), want (true,nil)", ok, err)
	}

	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetRoles(c2, []string{"admin"})
	if ok, _ := IsSuperAdminInContext(c2); ok {
		t.Error("admin should not be reported as super_admin")
	}
}
