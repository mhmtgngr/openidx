// Package auth provides context helper functions for RBAC in OpenIDX
package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
)

var (
	// ErrContextMissing is returned when context is missing
	ErrContextMissing = errors.New("gin context is missing")

	// ErrUserNotFound is returned when user_id is not found in context
	ErrUserNotFound = errors.New("user not found in context")

	// ErrRolesNotFound is returned when roles are not found in context
	ErrRolesNotFound = errors.New("roles not found in context")

	// ErrTenantNotFound is returned when tenant_id is not found in context
	ErrTenantNotFound = errors.New("tenant not found in context")
)

// Context key constants for storing values in Gin context
const (
	ContextKeyUserID   = "user_id"
	ContextKeyTenantID = "tenant_id"
	ContextKeyRoles    = "roles"
)

// UserInfo represents the authenticated user information from context
type UserInfo struct {
	UserID   string
	TenantID string
	Roles    []Role
}

// GetUserFromContext extracts the user ID from the Gin context
func GetUserFromContext(c *gin.Context) (string, error) {
	if c == nil {
		return "", ErrContextMissing
	}

	userID, exists := c.Get(ContextKeyUserID)
	if !exists {
		return "", ErrUserNotFound
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return "", errors.New("user_id in context is not a string")
	}

	return userIDStr, nil
}

// GetRolesFromContext extracts the roles from the Gin context
func GetRolesFromContext(c *gin.Context) ([]string, error) {
	if c == nil {
		return nil, ErrContextMissing
	}

	roles, exists := c.Get(ContextKeyRoles)
	if !exists {
		return nil, ErrRolesNotFound
	}

	rolesList, ok := roles.([]string)
	if !ok {
		return nil, errors.New("roles in context is not a string slice")
	}

	return rolesList, nil
}

// GetTypedRolesFromContext extracts the roles from the Gin context as Role types
func GetTypedRolesFromContext(c *gin.Context) ([]Role, error) {
	rolesList, err := GetRolesFromContext(c)
	if err != nil {
		return nil, err
	}

	typedRoles := make([]Role, len(rolesList))
	for i, r := range rolesList {
		typedRoles[i] = Role(r)
	}

	return typedRoles, nil
}

// GetTenantFromContext extracts the tenant ID from the Gin context
func GetTenantFromContext(c *gin.Context) (string, error) {
	if c == nil {
		return "", ErrContextMissing
	}

	tenantID, exists := c.Get(ContextKeyTenantID)
	if !exists {
		return "", ErrTenantNotFound
	}

	tenantIDStr, ok := tenantID.(string)
	if !ok {
		return "", errors.New("tenant_id in context is not a string")
	}

	return tenantIDStr, nil
}

// GetUserInfo extracts all user information from the Gin context
func GetUserInfo(c *gin.Context) (*UserInfo, error) {
	if c == nil {
		return nil, ErrContextMissing
	}

	userID, err := GetUserFromContext(c)
	if err != nil {
		return nil, err
	}

	tenantID, err := GetTenantFromContext(c)
	if err != nil {
		return nil, err
	}

	rolesList, err := GetRolesFromContext(c)
	if err != nil {
		return nil, err
	}

	typedRoles := make([]Role, len(rolesList))
	for i, r := range rolesList {
		typedRoles[i] = Role(r)
	}

	return &UserInfo{
		UserID:   userID,
		TenantID: tenantID,
		Roles:    typedRoles,
	}, nil
}

// HasRoleInContext checks if the user in context has a specific role
func HasRoleInContext(c *gin.Context, role Role) (bool, error) {
	roles, err := GetTypedRolesFromContext(c)
	if err != nil {
		return false, err
	}

	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}

// HasPermissionInContext checks if the user in context has a specific permission
func HasPermissionInContext(c *gin.Context, resource, action string) (bool, error) {
	roles, err := GetTypedRolesFromContext(c)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if HasPermission(role, resource, action) {
			return true, nil
		}
	}

	return false, nil
}

// IsAdminInContext checks if the user in context has admin privileges or higher
func IsAdminInContext(c *gin.Context) (bool, error) {
	roles, err := GetTypedRolesFromContext(c)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role.IsHigherOrEqual(RoleAdmin) {
			return true, nil
		}
	}

	return false, nil
}

// IsSuperAdminInContext checks if the user in context has super_admin role
func IsSuperAdminInContext(c *gin.Context) (bool, error) {
	return HasRoleInContext(c, RoleSuperAdmin)
}

// SetUserInContext sets user information in the Gin context
// This is useful for testing or when manually setting context
func SetUserInContext(c *gin.Context, userID, tenantID string, roles []string) {
	c.Set(ContextKeyUserID, userID)
	c.Set(ContextKeyTenantID, tenantID)
	c.Set(ContextKeyRoles, roles)
}

// SetUserID sets the user ID in the Gin context
func SetUserID(c *gin.Context, userID string) {
	c.Set(ContextKeyUserID, userID)
}

// SetTenantID sets the tenant ID in the Gin context
func SetTenantID(c *gin.Context, tenantID string) {
	c.Set(ContextKeyTenantID, tenantID)
}

// SetRoles sets the roles in the Gin context
func SetRoles(c *gin.Context, roles []string) {
	c.Set(ContextKeyRoles, roles)
}
