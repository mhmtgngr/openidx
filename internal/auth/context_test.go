// Package auth provides unit tests for context helpers
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetUserFromContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyUserID, "user123")

	userID, err := GetUserFromContext(c)
	if err != nil {
		t.Fatalf("GetUserFromContext failed: %v", err)
	}

	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got '%s'", userID)
	}
}

func TestGetUserFromContext_NilContext(t *testing.T) {
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

func TestGetUserFromContext_WrongType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyUserID, 123) // Set as int instead of string

	_, err := GetUserFromContext(c)
	if err == nil {
		t.Error("Expected error when userID is wrong type")
	}
}

func TestGetRolesFromContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	expectedRoles := []string{"admin", "auditor"}
	c.Set(ContextKeyRoles, expectedRoles)

	roles, err := GetRolesFromContext(c)
	if err != nil {
		t.Fatalf("GetRolesFromContext failed: %v", err)
	}

	if len(roles) != len(expectedRoles) {
		t.Errorf("Expected %d roles, got %d", len(expectedRoles), len(roles))
	}

	for i, role := range roles {
		if role != expectedRoles[i] {
			t.Errorf("Role at index %d: expected %s, got %s", i, expectedRoles[i], role)
		}
	}
}

func TestGetRolesFromContext_NilContext(t *testing.T) {
	_, err := GetRolesFromContext(nil)
	if err != ErrContextMissing {
		t.Errorf("Expected ErrContextMissing, got %v", err)
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

func TestGetRolesFromContext_WrongType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyRoles, "not-a-slice") // Set as string instead of slice

	_, err := GetRolesFromContext(c)
	if err == nil {
		t.Error("Expected error when roles is wrong type")
	}
}

func TestGetTypedRolesFromContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyRoles, []string{"admin", "operator"})

	roles, err := GetTypedRolesFromContext(c)
	if err != nil {
		t.Fatalf("GetTypedRolesFromContext failed: %v", err)
	}

	if len(roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(roles))
	}

	if roles[0] != RoleAdmin {
		t.Errorf("Expected first role to be RoleAdmin, got %v", roles[0])
	}

	if roles[1] != RoleOperator {
		t.Errorf("Expected second role to be RoleOperator, got %v", roles[1])
	}
}

func TestGetTenantFromContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyTenantID, "tenant456")

	tenantID, err := GetTenantFromContext(c)
	if err != nil {
		t.Fatalf("GetTenantFromContext failed: %v", err)
	}

	if tenantID != "tenant456" {
		t.Errorf("Expected tenantID 'tenant456', got '%s'", tenantID)
	}
}

func TestGetTenantFromContext_NilContext(t *testing.T) {
	_, err := GetTenantFromContext(nil)
	if err != ErrContextMissing {
		t.Errorf("Expected ErrContextMissing, got %v", err)
	}
}

func TestGetTenantFromContext_NotSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, err := GetTenantFromContext(c)
	if err != ErrTenantNotFound {
		t.Errorf("Expected ErrTenantNotFound, got %v", err)
	}
}

func TestGetTenantFromContext_WrongType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyTenantID, 123) // Set as int instead of string

	_, err := GetTenantFromContext(c)
	if err == nil {
		t.Error("Expected error when tenantID is wrong type")
	}
}

func TestGetUserInfo_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin", "auditor"})

	userInfo, err := GetUserInfo(c)
	if err != nil {
		t.Fatalf("GetUserInfo failed: %v", err)
	}

	if userInfo.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got '%s'", userInfo.UserID)
	}

	if userInfo.TenantID != "tenant456" {
		t.Errorf("Expected TenantID 'tenant456', got '%s'", userInfo.TenantID)
	}

	if len(userInfo.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(userInfo.Roles))
	}
}

func TestGetUserInfo_NilContext(t *testing.T) {
	_, err := GetUserInfo(nil)
	if err != ErrContextMissing {
		t.Errorf("Expected ErrContextMissing, got %v", err)
	}
}

func TestGetUserInfo_MissingUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyTenantID, "tenant456")
	c.Set(ContextKeyRoles, []string{"admin"})

	_, err := GetUserInfo(c)
	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestHasRoleInContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin", "auditor"})

	hasAdmin, err := HasRoleInContext(c, RoleAdmin)
	if err != nil {
		t.Fatalf("HasRoleInContext failed: %v", err)
	}

	if !hasAdmin {
		t.Error("Expected user to have admin role")
	}

	hasSuperAdmin, err := HasRoleInContext(c, RoleSuperAdmin)
	if err != nil {
		t.Fatalf("HasRoleInContext failed: %v", err)
	}

	if hasSuperAdmin {
		t.Error("Expected user to NOT have super_admin role")
	}
}

func TestHasRoleInContext_NoRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, err := HasRoleInContext(c, RoleAdmin)
	if err != ErrRolesNotFound {
		t.Errorf("Expected ErrRolesNotFound, got %v", err)
	}
}

func TestHasPermissionInContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin"})

	hasUsersDelete, err := HasPermissionInContext(c, "users", "delete")
	if err != nil {
		t.Fatalf("HasPermissionInContext failed: %v", err)
	}

	if !hasUsersDelete {
		t.Error("Expected admin to have users:delete permission")
	}

	hasTenantsManage, err := HasPermissionInContext(c, "tenants", "manage")
	if err != nil {
		t.Fatalf("HasPermissionInContext failed: %v", err)
	}

	if hasTenantsManage {
		t.Error("Expected admin to NOT have tenants:manage permission")
	}
}

func TestHasPermissionInContext_Hierarchy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"super_admin"})

	// Super admin inherits all permissions
	hasTenantsManage, err := HasPermissionInContext(c, "tenants", "manage")
	if err != nil {
		t.Fatalf("HasPermissionInContext failed: %v", err)
	}

	if !hasTenantsManage {
		t.Error("Expected super_admin to have tenants:manage permission")
	}
}

func TestHasPermissionInContext_NoRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, err := HasPermissionInContext(c, "users", "read")
	if err != ErrRolesNotFound {
		t.Errorf("Expected ErrRolesNotFound, got %v", err)
	}
}

func TestIsAdminInContext_Success(t *testing.T) {
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
		{"admin in multiple roles", []string{"user", "admin"}, true},
		{"super_admin in multiple roles", []string{"user", "super_admin"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			SetUserInContext(c, "user123", "tenant456", tt.roles)

			isAdmin, err := IsAdminInContext(c)
			if err != nil {
				t.Fatalf("IsAdminInContext failed: %v", err)
			}

			if isAdmin != tt.expected {
				t.Errorf("IsAdminInContext() = %v, want %v", isAdmin, tt.expected)
			}
		})
	}
}

func TestIsAdminInContext_NoRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	isAdmin, err := IsAdminInContext(c)
	if err != ErrRolesNotFound {
		t.Errorf("Expected ErrRolesNotFound, got %v", err)
	}

	if isAdmin {
		t.Error("Expected isAdmin to be false when roles not found")
	}
}

func TestIsSuperAdminInContext_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"super_admin"})

	isSuperAdmin, err := IsSuperAdminInContext(c)
	if err != nil {
		t.Fatalf("IsSuperAdminInContext failed: %v", err)
	}

	if !isSuperAdmin {
		t.Error("Expected user to be super_admin")
	}
}

func TestIsSuperAdminInContext_NotSuperAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin"})

	isSuperAdmin, err := IsSuperAdminInContext(c)
	if err != nil {
		t.Fatalf("IsSuperAdminInContext failed: %v", err)
	}

	if isSuperAdmin {
		t.Error("Expected admin to NOT be super_admin")
	}
}

func TestSetUserInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin"})

	// Verify all values were set
	userID, err := GetUserFromContext(c)
	if err != nil {
		t.Fatalf("GetUserFromContext failed: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got '%s'", userID)
	}

	tenantID, err := GetTenantFromContext(c)
	if err != nil {
		t.Fatalf("GetTenantFromContext failed: %v", err)
	}
	if tenantID != "tenant456" {
		t.Errorf("Expected tenantID 'tenant456', got '%s'", tenantID)
	}

	roles, err := GetRolesFromContext(c)
	if err != nil {
		t.Fatalf("GetRolesFromContext failed: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("Expected roles ['admin'], got %v", roles)
	}
}

func TestSetUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserID(c, "user999")

	userID, err := GetUserFromContext(c)
	if err != nil {
		t.Fatalf("GetUserFromContext failed: %v", err)
	}

	if userID != "user999" {
		t.Errorf("Expected userID 'user999', got '%s'", userID)
	}
}

func TestSetTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetTenantID(c, "tenant999")

	tenantID, err := GetTenantFromContext(c)
	if err != nil {
		t.Fatalf("GetTenantFromContext failed: %v", err)
	}

	if tenantID != "tenant999" {
		t.Errorf("Expected tenantID 'tenant999', got '%s'", tenantID)
	}
}

func TestSetRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	roles := []string{"operator", "auditor"}
	SetRoles(c, roles)

	retrievedRoles, err := GetRolesFromContext(c)
	if err != nil {
		t.Fatalf("GetRolesFromContext failed: %v", err)
	}

	if len(retrievedRoles) != len(roles) {
		t.Errorf("Expected %d roles, got %d", len(roles), len(retrievedRoles))
	}

	for i, role := range retrievedRoles {
		if role != roles[i] {
			t.Errorf("Role at index %d: expected %s, got %s", i, roles[i], role)
		}
	}
}

func TestContextKeyConstants(t *testing.T) {
	// Verify context key constants are unique
	keys := map[string]bool{
		ContextKeyUserID:   true,
		ContextKeyTenantID: true,
		ContextKeyRoles:    true,
	}

	if len(keys) != 3 {
		t.Error("Context key constants are not unique")
	}

	// Verify they have the expected values
	expectedKeys := map[string]string{
		ContextKeyUserID:   "user_id",
		ContextKeyTenantID: "tenant_id",
		ContextKeyRoles:    "roles",
	}

	for key, expected := range expectedKeys {
		if key != expected {
			t.Errorf("Context key constant: expected '%s', got '%s'", expected, key)
		}
	}
}

func TestUserInfo_Struct(t *testing.T) {
	userInfo := UserInfo{
		UserID:   "user123",
		TenantID: "tenant456",
		Roles:    []Role{RoleAdmin, RoleAuditor},
	}

	if userInfo.UserID != "user123" {
		t.Errorf("UserInfo.UserID = %s, want user123", userInfo.UserID)
	}

	if userInfo.TenantID != "tenant456" {
		t.Errorf("UserInfo.TenantID = %s, want tenant456", userInfo.TenantID)
	}

	if len(userInfo.Roles) != 2 {
		t.Errorf("UserInfo.Roles has %d elements, want 2", len(userInfo.Roles))
	}
}

// Test integration with actual Gin request
func TestContextInGinRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		SetUserInContext(c, "user123", "tenant456", []string{"admin"})

		userID, err := GetUserFromContext(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		roles, err := GetRolesFromContext(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id": userID,
			"roles":   roles,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// Benchmark tests
func BenchmarkGetUserFromContext(b *testing.B) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyUserID, "user123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetUserFromContext(c)
	}
}

func BenchmarkGetRolesFromContext(b *testing.B) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ContextKeyRoles, []string{"admin", "auditor", "operator"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetRolesFromContext(c)
	}
}

func BenchmarkGetUserInfo(b *testing.B) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetUserInfo(c)
	}
}

func BenchmarkHasPermissionInContext(b *testing.B) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetUserInContext(c, "user123", "tenant456", []string{"admin"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasPermissionInContext(c, "users", "read")
	}
}
