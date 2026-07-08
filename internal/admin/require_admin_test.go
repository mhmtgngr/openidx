package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// adminGateRouter wires the (production-used) RequireAdmin gate behind an
// injector that seeds the request context, then a terminal 200 handler.
func adminGateRouter(inject gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/a", inject, RequireAdmin(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// TestRequireAdmin covers the admin authorization gate used on privileged route
// groups (e.g. the vault group in admin-api). Only admin/super_admin pass; every
// other case — including a missing or malformed roles claim — fails closed (403).
func TestRequireAdmin(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*gin.Context)
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
			adminGateRouter(tc.setup).ServeHTTP(w, httptest.NewRequest("GET", "/a", nil))
			if w.Code != tc.want {
				t.Errorf("RequireAdmin[%s] = %d, want %d (body=%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
