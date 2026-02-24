// Package handlers provides route registration for admin console endpoints
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DashboardRoutes registers dashboard-related routes
func DashboardRoutes(router *gin.RouterGroup, handler *DashboardHandler) {
	dashboard := router.Group("/dashboard")
	{
		dashboard.GET("", handler.GetDashboardStats)
		dashboard.GET("/metrics", handler.GetMetrics)
		dashboard.POST("/refresh", handler.RefreshCache)
	}
}

// SettingsRoutes registers settings-related routes
func SettingsRoutes(router *gin.RouterGroup, handler *SettingsHandler) {
	settings := router.Group("/settings")
	{
		settings.GET("", handler.GetSettings)
		settings.PUT("", handler.UpdateSettings)
		settings.POST("/reset", handler.ResetSettings)
		settings.GET("/json", handler.GetSettingsJSON)
		settings.POST("/validate-password", handler.ValidatePassword)
	}
}

// RegisterAllRoutes registers all admin console routes
func RegisterAllRoutes(router *gin.RouterGroup, db *pgxpool.Pool, logger *zap.Logger) {
	dashboardHandler := NewDashboardHandler(logger, db)
	settingsHandler := NewSettingsHandler(logger, db)

	// Dashboard routes
	DashboardRoutes(router, dashboardHandler)

	// Settings routes
	SettingsRoutes(router, settingsHandler)
}
