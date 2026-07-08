package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

func requireAnyPermRouter(t *testing.T, inject gin.HandlerFunc, perms ...string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	m := NewRBACMiddleware(RBACConfig{Logger: zaptest.NewLogger(t)})
	r := gin.New()
	r.GET("/r", inject, m.RequireAnyPermission(perms...), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireAnyPermission_DeniedNoRoles(t *testing.T) {
	r := requireAnyPermRouter(t, func(c *gin.Context) { c.Next() }, "users:read")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("no roles: got %d, want 403", w.Code)
	}
}

func TestRequireAnyPermission_DeniedInvalidRolesFormat(t *testing.T) {
	r := requireAnyPermRouter(t, func(c *gin.Context) {
		c.Set(ContextKeyRoles, "not-a-slice")
		c.Next()
	}, "users:read")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("bad roles format: got %d, want 403", w.Code)
	}
}

// A malformed required permission (no resource:action colon) is a server
// misconfiguration → 500, not a silent allow.
func TestRequireAnyPermission_InvalidPermissionFormat(t *testing.T) {
	r := requireAnyPermRouter(t, func(c *gin.Context) {
		SetUserInContext(c, "u", "t", []string{"admin"})
		c.Next()
	}, "invalidformat")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("invalid permission format: got %d, want 500", w.Code)
	}
}
