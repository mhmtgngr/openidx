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

// RequireAdmin is a convenience middleware for admin/super_admin routes
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin", "super_admin")
}
