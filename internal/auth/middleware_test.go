// Package auth provides unit tests for RBAC middleware
package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// MockTokenValidator is a mock implementation of TokenValidator for testing
type MockTokenValidator struct {
	ValidToken   bool
	ExpiredToken bool
	UserID       string
	TenantID     string
	Roles        []string
	ShouldFail   bool
}

func (m *MockTokenValidator) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	if m.ShouldFail {
		return nil, ErrTokenInvalid
	}
	if m.ExpiredToken {
		return nil, ErrTokenExpired
	}
	if !m.ValidToken {
		return nil, ErrTokenInvalid
	}

	return &Claims{
		Subject:   m.UserID,
		TenantID:  m.TenantID,
		Roles:     m.Roles,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, nil
}

func TestAuthenticate_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{
		ValidToken: true,
		UserID:     "user123",
		TenantID:   "tenant456",
		Roles:      []string{"admin"},
	}

	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthenticate_MissingAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{
		ValidToken: true,
	}

	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	body := w.Body.String()
	if !contains(body, ErrMissingAuthHeader.Error()) {
		t.Errorf("Expected error about missing auth header, got: %s", body)
	}
}

func TestAuthenticate_InvalidAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{ValidToken: true}
	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthenticate_ExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{
		ExpiredToken: true,
	}

	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for expired token, got %d", w.Code)
	}

	body := w.Body.String()
	if !contains(body, ErrTokenExpired.Error()) {
		t.Errorf("Expected error about expired token, got: %s", body)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{
		ValidToken: false,
	}

	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid token, got %d", w.Code)
	}
}

func TestRequireRole_AdminAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/admin", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})
		c.Next()
	}, middleware.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin, got %d", w.Code)
	}
}

func TestRequireRole_UserDeniedAdminRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/admin", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"user"})
		c.Next()
	}, middleware.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for user on admin route, got %d", w.Code)
	}
}

func TestRequireRole_SuperAdminInheritsAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/admin", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"super_admin"})
		c.Next()
	}, middleware.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for super_admin on admin route (hierarchy), got %d", w.Code)
	}
}

func TestRequireRole_NoRolesInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/admin", middleware.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 when no roles in context, got %d", w.Code)
	}
}

func TestRequirePermission_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/users", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})
		c.Next()
	}, middleware.RequirePermission("users:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "users read granted"})
	})

	req := httptest.NewRequest("GET", "/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin with users:read, got %d", w.Code)
	}
}

func TestRequirePermission_InsufficientPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.DELETE("/users", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"auditor"})
		c.Next()
	}, middleware.RequirePermission("users:delete"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "users delete granted"})
	})

	req := httptest.NewRequest("DELETE", "/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for auditor attempting users:delete, got %d", w.Code)
	}
}

func TestRequirePermission_MultiplePermissions_AllRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.POST("/users", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})
		c.Next()
	}, middleware.RequirePermission("users:write", "users:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "users write granted"})
	})

	req := httptest.NewRequest("POST", "/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin with multiple permissions, got %d", w.Code)
	}
}

func TestRequirePermission_MultiplePermissions_MissingOne(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.DELETE("/users", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"operator"})
		c.Next()
	}, middleware.RequirePermission("users:delete", "tenants:manage"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "users delete granted"})
	})

	req := httptest.NewRequest("DELETE", "/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for operator missing tenants:manage, got %d", w.Code)
	}
}

func TestRequireAny_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/reports", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"auditor"})
		c.Next()
	}, middleware.RequireAny("admin", "auditor", "operator"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/reports", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for auditor in any-of check, got %d", w.Code)
	}
}

func TestRequireAny_Failure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/reports", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"user"})
		c.Next()
	}, middleware.RequireAny("admin", "auditor", "operator"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/reports", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for user in any-of check, got %d", w.Code)
	}
}

func TestRequireAnyPermission_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/audit", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"auditor"})
		c.Next()
	}, middleware.RequireAnyPermission("audit:read", "users:write"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/audit", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for auditor with audit:read, got %d", w.Code)
	}
}

func TestRequireAnyPermission_Failure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/audit", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"user"})
		c.Next()
	}, middleware.RequireAnyPermission("audit:export", "tenants:manage"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/audit", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for user with no matching permissions, got %d", w.Code)
	}
}

func TestRequireAllRoles_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/special", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin", "auditor"})
		c.Next()
	}, middleware.RequireAllRoles("admin", "auditor"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/special", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for user with both roles, got %d", w.Code)
	}
}

func TestRequireAllRoles_Failure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/special", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})
		c.Next()
	}, middleware.RequireAllRoles("admin", "auditor"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/special", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for user missing one role, got %d", w.Code)
	}
}

func TestRequireAllRoles_WithHierarchy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	// Super_admin inherits admin, so requiring both admin and user should pass
	router := gin.New()
	router.GET("/special", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"super_admin"})
		c.Next()
	}, middleware.RequireAllRoles("admin", "user"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	req := httptest.NewRequest("GET", "/special", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for super_admin with inherited roles, got %d", w.Code)
	}
}

func TestRoleHierarchy_SuperAdminInheritsAll(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission string
		expected   bool
	}{
		{"super_admin has users:delete", RoleSuperAdmin, "users:delete", true},
		{"super_admin has tenants:manage", RoleSuperAdmin, "tenants:manage", true},
		{"super_admin has config:manage", RoleSuperAdmin, "config:manage", true},
		{"super_admin has audit:export", RoleSuperAdmin, "audit:export", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitPermission(tt.permission)
			result := HasPermission(tt.role, parts[0], parts[1])
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestRoleHierarchy_AdminInheritsBelow(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission string
		expected   bool
	}{
		{"admin has users:delete", RoleAdmin, "users:delete", true},
		{"admin has groups:manage", RoleAdmin, "groups:manage", true},
		{"admin has audit:read", RoleAdmin, "audit:read", true},
		{"admin does NOT have tenants:manage", RoleAdmin, "tenants:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitPermission(tt.permission)
			result := HasPermission(tt.role, parts[0], parts[1])
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestRoleHierarchy_OperatorPermissions(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission string
		expected   bool
	}{
		{"operator has users:write", RoleOperator, "users:write", true},
		{"operator has groups:manage", RoleOperator, "groups:manage", true},
		{"operator has audit:read", RoleOperator, "audit:read", true},
		{"operator does NOT have users:delete", RoleOperator, "users:delete", false},
		{"operator does NOT have config:manage", RoleOperator, "config:manage", false},
		{"operator does NOT have tenants:manage", RoleOperator, "tenants:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitPermission(tt.permission)
			result := HasPermission(tt.role, parts[0], parts[1])
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestRoleHierarchy_AuditorPermissions(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission string
		expected   bool
	}{
		{"auditor has audit:read", RoleAuditor, "audit:read", true},
		{"auditor has audit:export", RoleAuditor, "audit:export", true},
		{"auditor has users:read", RoleAuditor, "users:read", true},
		{"auditor does NOT have users:write", RoleAuditor, "users:write", false},
		{"auditor does NOT have users:delete", RoleAuditor, "users:delete", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitPermission(tt.permission)
			result := HasPermission(tt.role, parts[0], parts[1])
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestRoleHierarchy_UserPermissions(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission string
		expected   bool
	}{
		{"user has users:read", RoleUser, "users:read", true},
		{"user does NOT have users:write", RoleUser, "users:write", false},
		{"user does NOT have audit:read", RoleUser, "audit:read", false},
		{"user does NOT have groups:manage", RoleUser, "groups:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitPermission(tt.permission)
			result := HasPermission(tt.role, parts[0], parts[1])
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

func TestIsHigherOrEqualRole(t *testing.T) {
	tests := []struct {
		name     string
		roleA    Role
		roleB    Role
		expected bool
	}{
		{"super_admin >= admin", RoleSuperAdmin, RoleAdmin, true},
		{"super_admin >= operator", RoleSuperAdmin, RoleOperator, true},
		{"admin >= operator", RoleAdmin, RoleOperator, true},
		{"operator >= auditor", RoleOperator, RoleAuditor, true},
		{"auditor >= user", RoleAuditor, RoleUser, true},
		{"admin >= admin (equal)", RoleAdmin, RoleAdmin, true},
		{"operator NOT >= admin", RoleOperator, RoleAdmin, false},
		{"user NOT >= operator", RoleUser, RoleOperator, false},
		{"auditor NOT >= admin", RoleAuditor, RoleAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHigherOrEqualRole(tt.roleA, tt.roleB)
			if result != tt.expected {
				t.Errorf("IsHigherOrEqualRole(%v, %v) = %v, want %v", tt.roleA, tt.roleB, result, tt.expected)
			}
		})
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		input    string
		expected Permission
		hasError bool
	}{
		{"users:read", Permission{Resource: "users", Action: "read"}, false},
		{"tenants:manage", Permission{Resource: "tenants", Action: "manage"}, false},
		{"invalid", Permission{}, true},
		{"", Permission{}, true},
		{":", Permission{Resource: "", Action: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParsePermission(tt.input)
			if tt.hasError {
				if err == nil {
					t.Errorf("ParsePermission(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePermission(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParsePermission(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestIsValidRole(t *testing.T) {
	tests := []struct {
		role     string
		expected bool
	}{
		{"super_admin", true},
		{"admin", true},
		{"operator", true},
		{"auditor", true},
		{"user", true},
		{"invalid", false},
		{"", false},
		{"SuperAdmin", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			result := IsValidRole(tt.role)
			if result != tt.expected {
				t.Errorf("IsValidRole(%q) = %v, want %v", tt.role, result, tt.expected)
			}
		})
	}
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func splitPermission(perm string) (result []string) {
	parts := make([]string, 2)
	for i, r := range perm {
		if r == ':' {
			parts[0] = perm[:i]
			parts[1] = perm[i+1:]
			return parts
		}
	}
	return []string{perm}
}

// Benchmark tests
func BenchmarkHasPermission(b *testing.B) {
	role := RoleAdmin
	resource := "users"
	action := "read"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasPermission(role, resource, action)
	}
}

func BenchmarkIsHigherOrEqualRole(b *testing.B) {
	roleA := RoleSuperAdmin
	roleB := RoleUser

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsHigherOrEqualRole(roleA, roleB)
	}
}

func TestGetPermissions(t *testing.T) {
	tests := []struct {
		name          string
		role          Role
		minPerms      int // Minimum expected permissions (including inherited)
		checkPerms    []Permission
		shouldHaveAll bool
	}{
		{
			name:     "super_admin has all permissions",
			role:     RoleSuperAdmin,
			minPerms: 9,
			checkPerms: []Permission{
				{"users", "read"},
				{"users", "write"},
				{"users", "delete"},
				{"groups", "manage"},
				{"config", "manage"},
				{"audit", "read"},
				{"audit", "export"},
				{"policies", "manage"},
				{"tenants", "manage"},
			},
			shouldHaveAll: true,
		},
		{
			name:     "admin inherits from operator, auditor, user",
			role:     RoleAdmin,
			minPerms: 8,
			checkPerms: []Permission{
				{"users", "read"},
				{"users", "write"},
				{"users", "delete"},
				{"groups", "manage"},
				{"audit", "read"},
				{"audit", "export"},
				{"policies", "manage"},
			},
			shouldHaveAll: true,
		},
		{
			name:     "auditor has limited permissions",
			role:     RoleAuditor,
			minPerms: 3,
			checkPerms: []Permission{
				{"audit", "read"},
				{"audit", "export"},
				{"users", "read"},
			},
			shouldHaveAll: true,
		},
		{
			name:     "user has minimal permissions",
			role:     RoleUser,
			minPerms: 1,
			checkPerms: []Permission{
				{"users", "read"},
			},
			shouldHaveAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := GetPermissions(tt.role)

			if len(perms) < tt.minPerms {
				t.Errorf("GetPermissions(%v) returned %d permissions, expected at least %d", tt.role, len(perms), tt.minPerms)
			}

			permMap := make(map[Permission]bool)
			for _, p := range perms {
				permMap[p] = true
			}

			for _, checkPerm := range tt.checkPerms {
				if tt.shouldHaveAll {
					if !permMap[checkPerm] {
						t.Errorf("GetPermissions(%v) missing permission %v", tt.role, checkPerm)
					}
				} else {
					if permMap[checkPerm] {
						t.Errorf("GetPermissions(%v) should not have permission %v", tt.role, checkPerm)
					}
				}
			}
		})
	}
}

// Test Permission String method
func TestPermission_String(t *testing.T) {
	perm := Permission{Resource: "users", Action: "read"}
	expected := "users:read"
	if perm.String() != expected {
		t.Errorf("Permission.String() = %s, want %s", perm.String(), expected)
	}
}

// Test Inherits method on Role
func TestRole_Inherits(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		child    Role
		expected bool
	}{
		{"super_admin inherits admin", RoleSuperAdmin, RoleAdmin, true},
		{"super_admin inherits user", RoleSuperAdmin, RoleUser, true},
		{"admin inherits operator", RoleAdmin, RoleOperator, true},
		{"admin inherits user", RoleAdmin, RoleUser, true},
		{"operator inherits user", RoleOperator, RoleUser, true},
		{"operator does NOT inherit admin", RoleOperator, RoleAdmin, false},
		{"user does NOT inherit anything", RoleUser, RoleOperator, false},
		{"admin does NOT inherit super_admin", RoleAdmin, RoleSuperAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.Inherits(tt.child)
			if result != tt.expected {
				t.Errorf("%v.Inherits(%v) = %v, want %v", tt.role, tt.child, result, tt.expected)
			}
		})
	}
}

// Test GetPermissions method on Role
func TestRole_GetPermissions(t *testing.T) {
	role := RoleAdmin
	perms := role.GetPermissions()

	if len(perms) == 0 {
		t.Error("GetPermissions returned empty slice for admin")
	}

	// Check for a key admin permission
	hasUsersWrite := false
	for _, p := range perms {
		if p.Resource == "users" && p.Action == "write" {
			hasUsersWrite = true
			break
		}
	}

	if !hasUsersWrite {
		t.Error("Admin permissions should include users:write")
	}
}

// Test IsHigherOrEqual method on Role
func TestRole_IsHigherOrEqual(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		other    Role
		expected bool
	}{
		{"super_admin >= admin", RoleSuperAdmin, RoleAdmin, true},
		{"admin >= operator", RoleAdmin, RoleOperator, true},
		{"operator >= user", RoleOperator, RoleUser, true},
		{"user NOT >= admin", RoleUser, RoleAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.IsHigherOrEqual(tt.other)
			if result != tt.expected {
				t.Errorf("%v.IsHigherOrEqual(%v) = %v, want %v", tt.role, tt.other, result, tt.expected)
			}
		})
	}
}

// Test Level method on Role
func TestRole_Level(t *testing.T) {
	tests := []struct {
		role     Role
		expected int
	}{
		{RoleSuperAdmin, 4},
		{RoleAdmin, 3},
		{RoleOperator, 2},
		{RoleAuditor, 1},
		{RoleUser, 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			result := tt.role.Level()
			if result != tt.expected {
				t.Errorf("%v.Level() = %d, want %d", tt.role, result, tt.expected)
			}
		})
	}
}

// Test HasPermission method on Role
func TestRole_HasPermission(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		resource string
		action   string
		expected bool
	}{
		{"admin has users:write", RoleAdmin, "users", "write", true},
		{"admin has audit:read", RoleAdmin, "audit", "read", true},
		{"admin does NOT have tenants:manage", RoleAdmin, "tenants", "manage", false},
		{"auditor has audit:read", RoleAuditor, "audit", "read", true},
		{"auditor does NOT have users:write", RoleAuditor, "users", "write", false},
		{"user has users:read", RoleUser, "users", "read", true},
		{"user does NOT have audit:read", RoleUser, "audit", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.HasPermission(tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("%v.HasPermission(%q, %q) = %v, want %v", tt.role, tt.resource, tt.action, result, tt.expected)
			}
		})
	}
}

// Test integration with full middleware chain
func TestFullMiddlewareChain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &MockTokenValidator{
		ValidToken: true,
		UserID:     "admin123",
		TenantID:   "tenant456",
		Roles:      []string{"admin"},
	}

	middleware := NewRBACMiddleware(RBACConfig{
		TokenValidator: validator,
		Logger:         zaptest.NewLogger(t),
	})

	router := gin.New()
	router.Use(middleware.Authenticate())

	// Admin route - requires admin role and specific permissions
	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.RequireRole("admin"))
	adminGroup.Use(middleware.RequirePermission("users:delete"))
	adminGroup.DELETE("/users/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
	})

	// Test successful request
	req := httptest.NewRequest("DELETE", "/admin/users/user123", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// Test that user without any role can still access public routes
func TestPublicRoute_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public access"})
	})

	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for public route, got %d", w.Code)
	}
}

// Test invalid permission format in RequirePermission
func TestRequirePermission_InvalidFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware := NewRBACMiddleware(RBACConfig{
		Logger: zaptest.NewLogger(t),
	})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})
		c.Next()
	}, middleware.RequirePermission("invalidformat"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should return 500 because of invalid permission format
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for invalid permission format, got %d", w.Code)
	}
}

// Test context helpers integration
func TestGetUserInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin", "auditor"})

	userInfo, err := GetUserInfo(c)
	if err != nil {
		t.Fatalf("GetUserInfo failed: %v", err)
	}

	if userInfo.UserID != "user123" {
		t.Errorf("Expected UserID user123, got %s", userInfo.UserID)
	}

	if userInfo.TenantID != "tenant456" {
		t.Errorf("Expected TenantID tenant456, got %s", userInfo.TenantID)
	}

	if len(userInfo.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(userInfo.Roles))
	}

	// Check for admin role
	hasAdmin := false
	for _, r := range userInfo.Roles {
		if r == RoleAdmin {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		t.Error("Expected admin role in user info")
	}
}

// Test IsAdminInContext
func TestIsAdminInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"admin is admin", []string{"admin"}, true},
		{"super_admin is admin", []string{"super_admin"}, true},
		{"operator is NOT admin", []string{"operator"}, false},
		{"auditor is NOT admin", []string{"auditor"}, false},
		{"user is NOT admin", []string{"user"}, false},
		{"admin+auditor is admin", []string{"admin", "auditor"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			SetUserInContext(c, "user123", "tenant456", tt.roles)

			result, err := IsAdminInContext(c)
			if err != nil {
				t.Fatalf("IsAdminInContext failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("IsAdminInContext() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test HasPermissionInContext
func TestHasPermissionInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		roles    []string
		resource string
		action   string
		expected bool
	}{
		{"admin has users:delete", []string{"admin"}, "users", "delete", true},
		{"auditor does NOT have users:delete", []string{"auditor"}, "users", "delete", false},
		{"operator has users:write", []string{"operator"}, "users", "write", true},
		{"user does NOT have audit:read", []string{"user"}, "audit", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			SetUserInContext(c, "user123", "tenant456", tt.roles)

			result, err := HasPermissionInContext(c, tt.resource, tt.action)
			if err != nil {
				t.Fatalf("HasPermissionInContext failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("HasPermissionInContext(%q, %q) = %v, want %v", tt.resource, tt.action, result, tt.expected)
			}
		})
	}
}

// Test context errors
func TestGetUserFromContext_NoContext(t *testing.T) {
	_, err := GetUserFromContext(nil)
	if err != ErrContextMissing {
		t.Errorf("Expected ErrContextMissing, got %v", err)
	}
}

func TestGetUserFromContext_NotSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, err := GetUserFromContext(c)
	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestGetRolesFromContext_NotSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, err := GetRolesFromContext(c)
	if err != ErrRolesNotFound {
		t.Errorf("Expected ErrRolesNotFound, got %v", err)
	}
}

// Test HasAllPermissions
func TestHasAllPermissions(t *testing.T) {
	tests := []struct {
		name        string
		role        Role
		permissions []Permission
		expected    bool
	}{
		{
			name: "admin has users:read and users:write",
			role: RoleAdmin,
			permissions: []Permission{
				{"users", "read"},
				{"users", "write"},
			},
			expected: true,
		},
		{
			name: "auditor does NOT have all admin permissions",
			role: RoleAuditor,
			permissions: []Permission{
				{"users", "read"},
				{"users", "delete"},
			},
			expected: false,
		},
		{
			name: "super_admin has all permissions",
			role: RoleSuperAdmin,
			permissions: []Permission{
				{"tenants", "manage"},
				{"config", "manage"},
				{"users", "delete"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllPermissions(tt.role, tt.permissions...)
			if result != tt.expected {
				t.Errorf("HasAllPermissions(%v, %v) = %v, want %v", tt.role, tt.permissions, result, tt.expected)
			}
		})
	}
}

// Test HasAnyPermission
func TestHasAnyPermission(t *testing.T) {
	tests := []struct {
		name        string
		role        Role
		permissions []Permission
		expected    bool
	}{
		{
			name: "auditor has at least one of admin permissions",
			role: RoleAuditor,
			permissions: []Permission{
				{"users", "delete"},
				{"audit", "read"},
				{"tenants", "manage"},
			},
			expected: true,
		},
		{
			name: "user has none of the specified permissions",
			role: RoleUser,
			permissions: []Permission{
				{"users", "delete"},
				{"audit", "export"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAnyPermission(tt.role, tt.permissions...)
			if result != tt.expected {
				t.Errorf("HasAnyPermission(%v, %v) = %v, want %v", tt.role, tt.permissions, result, tt.expected)
			}
		})
	}
}

// Test ParseRole
func TestParseRole(t *testing.T) {
	tests := []struct {
		input    string
		expected Role
		hasError bool
	}{
		{"super_admin", RoleSuperAdmin, false},
		{"admin", RoleAdmin, false},
		{"operator", RoleOperator, false},
		{"auditor", RoleAuditor, false},
		{"user", RoleUser, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseRole(tt.input)
			if tt.hasError {
				if err == nil {
					t.Errorf("ParseRole(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseRole(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseRole(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}
