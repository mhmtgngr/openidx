package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
)

// TestAppsRoutes_requireAdminRole covers the gate now applied to the app-publish
// (/apps) routes in RegisterRoutes. App publishing (register an internal app →
// discover paths → publish as a proxy route) is an admin operation that exposes
// infrastructure, so — like every sibling management surface (ziti/*, guacamole
// credentials, temp-access) — the routes carry `adminOnly`. Before this, any
// authenticated user could register/discover/publish/delete published apps.
//
// Only admin/super_admin pass; missing, malformed, non-admin, or empty roles
// fail closed with 403. The development bypass is exercised separately.
func TestAppsRoutes_requireAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Gate enforces by default in any env; DevAdminBypass is the only bypass.
	s := &Service{config: &config.Config{Environment: "production"}}

	router := func(inject gin.HandlerFunc) *gin.Engine {
		r := gin.New()
		r.GET("/apps", inject, s.requireAdminRole(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})
		return r
	}

	cases := []struct {
		name  string
		setup gin.HandlerFunc
		want  int
	}{
		{"admin allowed", func(c *gin.Context) { c.Set("roles", []string{"admin"}); c.Next() }, http.StatusOK},
		{"super_admin allowed", func(c *gin.Context) { c.Set("roles", []string{"super_admin"}); c.Next() }, http.StatusOK},
		{"admin among others", func(c *gin.Context) { c.Set("roles", []string{"user", "admin"}); c.Next() }, http.StatusOK},
		{"non-admin denied", func(c *gin.Context) { c.Set("roles", []string{"user"}); c.Next() }, http.StatusForbidden},
		{"no roles denied", func(c *gin.Context) { c.Next() }, http.StatusForbidden},
		{"malformed roles denied", func(c *gin.Context) { c.Set("roles", "not-a-slice"); c.Next() }, http.StatusForbidden},
		{"empty roles denied", func(c *gin.Context) { c.Set("roles", []string{}); c.Next() }, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router(tc.setup).ServeHTTP(w, httptest.NewRequest("GET", "/apps", nil))
			if w.Code != tc.want {
				t.Errorf("requireAdminRole[%s] = %d, want %d (body=%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}

	// APP_ENV=development ALONE must NOT bypass the gate — a box left in dev
	// mode must still keep admin mutations behind identity. The bypass is now an
	// explicit opt-in (DevAdminBypass).
	t.Run("dev env alone does not bypass", func(t *testing.T) {
		dev := &Service{config: &config.Config{Environment: "development"}}
		r := gin.New()
		r.GET("/apps", dev.requireAdminRole(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/apps", nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("dev env alone should NOT bypass gate, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	// DevAdminBypass=true is the explicit local-convenience opt-in.
	t.Run("DevAdminBypass opt-in bypasses", func(t *testing.T) {
		dev := &Service{config: &config.Config{Environment: "development", DevAdminBypass: true}}
		r := gin.New()
		r.GET("/apps", dev.requireAdminRole(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/apps", nil))
		if w.Code != http.StatusOK {
			t.Errorf("DevAdminBypass should bypass gate, got %d (body=%s)", w.Code, w.Body.String())
		}
	})
}
