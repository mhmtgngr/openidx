package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

// requireAnyRouter builds a router whose /r route injects the given roles (or a
// raw context value when rawRoles is set) and then enforces RequireAny(required...).
func requireAnyRouter(t *testing.T, inject gin.HandlerFunc, required ...string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	m := NewRBACMiddleware(RBACConfig{Logger: zaptest.NewLogger(t)})
	r := gin.New()
	r.GET("/r", inject, m.RequireAny(required...), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireAny_AllowedDirectMatch(t *testing.T) {
	r := requireAnyRouter(t, func(c *gin.Context) {
		SetUserInContext(c, "u", "t", []string{"operator"})
		c.Next()
	}, "admin", "operator")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusOK {
		t.Errorf("direct match: got %d, want 200", w.Code)
	}
}

func TestRequireAny_AllowedViaHierarchy(t *testing.T) {
	// super_admin outranks admin → RequireAny("admin") is satisfied.
	r := requireAnyRouter(t, func(c *gin.Context) {
		SetUserInContext(c, "u", "t", []string{string(RoleSuperAdmin)})
		c.Next()
	}, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusOK {
		t.Errorf("hierarchy: got %d, want 200", w.Code)
	}
}

func TestRequireAny_DeniedNoMatchingRole(t *testing.T) {
	r := requireAnyRouter(t, func(c *gin.Context) {
		SetUserInContext(c, "u", "t", []string{"user"})
		c.Next()
	}, "admin", "operator")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("no matching role: got %d, want 403", w.Code)
	}
}

func TestRequireAny_DeniedNoRolesInContext(t *testing.T) {
	r := requireAnyRouter(t, func(c *gin.Context) { c.Next() }, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("no roles in context: got %d, want 403", w.Code)
	}
}

func TestRequireAny_DeniedInvalidRolesFormat(t *testing.T) {
	r := requireAnyRouter(t, func(c *gin.Context) {
		c.Set(ContextKeyRoles, "not-a-slice")
		c.Next()
	}, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("invalid roles format: got %d, want 403", w.Code)
	}
}
