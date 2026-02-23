// Package admin provides handler wiring with role-based middleware for the admin console
package admin

import (
	"github.com/gin-gonic/gin"
)

// RequireRole is a middleware that requires specific roles to access the endpoint
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("roles")
		if !exists {
			c.JSON(403, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			c.JSON(403, gin.H{"error": "invalid role format"})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		for _, required := range roles {
			for _, userRole := range userRolesList {
				if userRole == required {
					c.Next()
					return
				}
			}
		}

		c.JSON(403, gin.H{"error": "insufficient permissions"})
		c.Abort()
	}
}

// RequirePermission checks if the user has a specific permission
func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permsRaw, exists := c.Get("permissions")
		if !exists {
			c.JSON(403, gin.H{"error": "permissions not resolved"})
			c.Abort()
			return
		}

		perms, ok := permsRaw.([]interface{})
		if !ok {
			c.JSON(403, gin.H{"error": "invalid permissions format"})
			c.Abort()
			return
		}

		// Check for matching permission
		for _, p := range perms {
			if permMap, ok := p.(map[string]interface{}); ok {
				if permResource, ok := permMap["resource"].(string); ok {
					if permAction, ok := permMap["action"].(string); ok {
						if permResource == resource && permAction == action {
							c.Next()
							return
						}
					}
				}
			}
		}

		c.JSON(403, gin.H{"error": "missing required permission"})
		c.Abort()
	}
}

// RegisterAdminRoutes registers all admin-specific routes with role-based protection
func RegisterAdminRoutes(router *gin.RouterGroup, svc *Service) {
	// Protected routes - require super_admin or admin role
	adminGroup := router.Group("/admin")
	adminGroup.Use(RequireRole("super_admin", "admin"))
	{
		// Enhanced dashboard
		adminGroup.GET("/dashboard", svc.handleGetEnhancedDashboardStats)

		// System configuration
		adminGroup.GET("/config", svc.handleGetSystemConfig)
		adminGroup.PUT("/config", svc.handleUpdateSystemConfig)
		adminGroup.POST("/config/reset", svc.handleResetSystemConfig)
		adminGroup.POST("/config/validate-password", svc.handleValidatePassword)

		// Tenant management
		adminGroup.GET("/tenants", svc.handleListTenants)
		adminGroup.POST("/tenants", svc.handleCreateTenant)
		adminGroup.GET("/tenants/:id", svc.handleGetTenant)
		adminGroup.PUT("/tenants/:id", svc.handleUpdateTenant)
		adminGroup.DELETE("/tenants/:id", svc.handleDeleteTenant)

		// Bulk user operations
		adminGroup.POST("/users/import", svc.handleImportUsersCSV)
		adminGroup.GET("/users/export", svc.handleExportUsersCSV)
		adminGroup.GET("/users/import/template", svc.handleGetImportTemplate)
	}

	// Super admin only routes
	superAdminGroup := router.Group("/admin")
	superAdminGroup.Use(RequireRole("super_admin"))
	{
		// Add super-admin-only endpoints here if needed
	}
}

// RegisterRoutesWithTenantIsolation registers routes with tenant isolation middleware
func RegisterRoutesWithTenantIsolation(router *gin.RouterGroup, svc *Service) {
	// Apply tenant isolation middleware to all admin routes
	tenantGroup := router.Group("/admin")
	tenantGroup.Use(svc.TenantIsolationMiddleware())
	{
		// Tenant-isolated routes
		RegisterAdminRoutes(tenantGroup, svc)
	}
}

// RegisterPublicAdminRoutes registers routes that don't require authentication
// but may have rate limiting or other restrictions
func RegisterPublicAdminRoutes(router *gin.RouterGroup, svc *Service) {
	// Public template download (rate limited should be applied at router level)
	publicGroup := router.Group("/admin")
	{
		publicGroup.GET("/users/import/template", svc.handleGetImportTemplate)
	}
}

// RequireSuperAdmin is a convenience middleware for super_admin only routes
func RequireSuperAdmin() gin.HandlerFunc {
	return RequireRole("super_admin")
}

// RequireAdmin is a convenience middleware for admin/super_admin routes
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin", "super_admin")
}

// RequireTenantAccess is a middleware that validates tenant access
// This works in conjunction with TenantIsolationMiddleware
func RequireTenantAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant from context (set by isolation middleware)
		requestTenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(400, gin.H{"error": "tenant context not set"})
			c.Abort()
			return
		}

		// Get user's tenant from JWT
		userTenantID, exists := c.Get("user_tenant_id")
		if !exists {
			// Admin users might not have tenant_id, they can access all
			c.Next()
			return
		}

		// Check if user belongs to the requested tenant
		if requestTenantID != userTenantID {
			c.JSON(403, gin.H{"error": "tenant access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// TenantScopedHandler wraps a handler to enforce tenant scoping
func TenantScopedHandler(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Inject tenant_id into query parameters for database queries
		if tenantID, exists := c.Get("tenant_id"); exists {
			if tenantStr, ok := tenantID.(string); ok {
				c.Set("query_tenant_id", tenantStr)
			}
		}
		handler(c)
	}
}
