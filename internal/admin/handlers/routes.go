// Package handlers provides route registration for admin console endpoints
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/auth"
)

// requireStaff admits a caller holding a role at operator level or above
// (super_admin, admin, operator), the roles the console's dashboard asks
// GET /dashboard for (dashboard.tsx: isStaff, roleLevel >= operator). A plain
// user gets a personal dashboard that never calls it. The route asked only for
// a signed-in user, and it answers with the organization's latest audit
// events, its failed-login and suspicious-IP counts and its user and session
// counts, so any account in the organization could read them.
func requireStaff(c *gin.Context) {
	for _, r := range c.GetStringSlice("roles") {
		if auth.Role(r).Level() >= auth.RoleOperator.Level() {
			c.Next()
			return
		}
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator access required"})
}

// DashboardRoutes registers dashboard-related routes
func DashboardRoutes(router *gin.RouterGroup, handler *DashboardHandler) {
	dashboard := router.Group("/dashboard")
	{
		dashboard.GET("", requireStaff, handler.GetDashboardStats)
		// GET /metrics and POST /refresh are gone. The first returned a zero
		// SystemMetrics while its swagger said "real-time CPU, memory and disk
		// usage"; the second answered "Dashboard cache refreshed successfully"
		// from a body that was one comment and one c.JSON, invalidating
		// nothing. An endpoint that reports success for work it does not do is
		// worse than a 404: the 404 is at least true.
	}
}

// SettingsRoutes registers settings-related routes. Mutating routes (update,
// reset) are guarded by adminMW so that only admins can change org-wide
// security/password policy; read and password-validation routes stay open to
// any authenticated caller. If adminMW is nil the guard is skipped.
func SettingsRoutes(router *gin.RouterGroup, handler *SettingsHandler, adminMW gin.HandlerFunc) {
	settings := router.Group("/settings")
	{
		settings.GET("", handler.GetSettings)
		settings.GET("/json", handler.GetSettingsJSON)
		settings.POST("/validate-password", handler.ValidatePassword)
	}

	// Mutations require admin.
	mutate := router.Group("/settings")
	if adminMW != nil {
		mutate.Use(adminMW)
	}
	{
		mutate.PUT("", handler.UpdateSettings)
		mutate.POST("/reset", handler.ResetSettings)
	}
}

// RegisterAllRoutes registers all admin console routes. adminMW guards the
// mutating settings endpoints; pass admin.RequireAdmin() from the caller.
func RegisterAllRoutes(router *gin.RouterGroup, db ScopedDB, logger *zap.Logger, adminMW gin.HandlerFunc) {
	dashboardHandler := NewDashboardHandler(logger, db)
	settingsHandler := NewSettingsHandler(logger, db)

	// Dashboard routes
	DashboardRoutes(router, dashboardHandler)

	// Settings routes
	SettingsRoutes(router, settingsHandler, adminMW)
}
