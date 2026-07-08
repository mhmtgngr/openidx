package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestSuperAdminPredicate locks in the cross-org privilege gate wired into every
// service's tenant resolver: only a super_admin is treated as a platform admin
// (may cross org boundaries via X-Org-ID); everything else — including a missing
// or malformed roles claim — must be denied.
func TestSuperAdminPredicate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name  string
		setup func(*gin.Context)
		want  bool
	}{
		{"super_admin only", func(c *gin.Context) { SetRoles(c, []string{string(RoleSuperAdmin)}) }, true},
		{"super_admin among others", func(c *gin.Context) { SetRoles(c, []string{"admin", string(RoleSuperAdmin)}) }, true},
		{"non-super roles only", func(c *gin.Context) { SetRoles(c, []string{"admin", "auditor"}) }, false},
		{"no roles set", func(c *gin.Context) {}, false},
		{"roles wrong type", func(c *gin.Context) { c.Set(ContextKeyRoles, "not-a-slice") }, false},
		{"empty roles slice", func(c *gin.Context) { SetRoles(c, []string{}) }, false},
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
