// Package routes provides admin API route registration for the gateway
package routes

import (
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterAdminRoutes registers routes for the admin API
func RegisterAdminRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("admin")
	if err != nil {
		serviceURL = "http://localhost:8505"
	}

	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Dashboard endpoints
	router.GET("/dashboard", proxyRequest(proxy))
	router.GET("/dashboard/stats", proxyRequest(proxy))

	// System settings
	router.GET("/settings", proxyRequest(proxy))
	router.PUT("/settings", proxyRequest(proxy))
	router.GET("/settings/:key", proxyRequest(proxy))
	router.PUT("/settings/:key", proxyRequest(proxy))

	// Application management
	router.GET("/applications", proxyRequest(proxy))
	router.POST("/applications", proxyRequest(proxy))
	router.GET("/applications/:id", proxyRequest(proxy))
	router.PUT("/applications/:id", proxyRequest(proxy))
	router.DELETE("/applications/:id", proxyRequest(proxy))

	// Application secrets
	router.GET("/applications/:id/secrets", proxyRequest(proxy))
	router.POST("/applications/:id/secrets", proxyRequest(proxy))
	router.PUT("/applications/:id/secrets/:secret_id", proxyRequest(proxy))
	router.DELETE("/applications/:id/secrets/:secret_id", proxyRequest(proxy))

	// API keys management
	router.GET("/api-keys", proxyRequest(proxy))
	router.POST("/api-keys", proxyRequest(proxy))
	router.GET("/api-keys/:id", proxyRequest(proxy))
	router.PUT("/api-keys/:id", proxyRequest(proxy))
	router.DELETE("/api-keys/:id", proxyRequest(proxy))

	// Webhooks
	router.GET("/webhooks", proxyRequest(proxy))
	router.POST("/webhooks", proxyRequest(proxy))
	router.GET("/webhooks/:id", proxyRequest(proxy))
	router.PUT("/webhooks/:id", proxyRequest(proxy))
	router.DELETE("/webhooks/:id", proxyRequest(proxy))
	router.POST("/webhooks/:id/test", proxyRequest(proxy))

	// Notification templates
	router.GET("/templates", proxyRequest(proxy))
	router.POST("/templates", proxyRequest(proxy))
	router.GET("/templates/:id", proxyRequest(proxy))
	router.PUT("/templates/:id", proxyRequest(proxy))
	router.DELETE("/templates/:id", proxyRequest(proxy))

	// System health and monitoring
	router.GET("/system/health", proxyRequest(proxy))
	router.GET("/system/metrics", proxyRequest(proxy))
	router.GET("/system/status", proxyRequest(proxy))

	// User management (admin operations)
	router.GET("/users", proxyRequest(proxy))
	router.POST("/users", proxyRequest(proxy))
	router.GET("/users/:id", proxyRequest(proxy))
	router.PUT("/users/:id", proxyRequest(proxy))
	router.DELETE("/users/:id", proxyRequest(proxy))
	router.POST("/users/:id/activate", proxyRequest(proxy))
	router.POST("/users/:id/deactivate", proxyRequest(proxy))

	// Organization management
	router.GET("/organizations", proxyRequest(proxy))
	router.POST("/organizations", proxyRequest(proxy))
	router.GET("/organizations/:id", proxyRequest(proxy))
	router.PUT("/organizations/:id", proxyRequest(proxy))
	router.DELETE("/organizations/:id", proxyRequest(proxy))

	// Role and permission management
	router.GET("/roles", proxyRequest(proxy))
	router.POST("/roles", proxyRequest(proxy))
	router.GET("/roles/:id", proxyRequest(proxy))
	router.PUT("/roles/:id", proxyRequest(proxy))
	router.DELETE("/roles/:id", proxyRequest(proxy))

	// Permission management
	router.GET("/permissions", proxyRequest(proxy))
	router.POST("/permissions", proxyRequest(proxy))
	router.GET("/permissions/:id", proxyRequest(proxy))
	router.PUT("/permissions/:id", proxyRequest(proxy))
	router.DELETE("/permissions/:id", proxyRequest(proxy))

	// Role permission assignments
	router.GET("/roles/:id/permissions", proxyRequest(proxy))
	router.POST("/roles/:id/permissions", proxyRequest(proxy))
	router.DELETE("/roles/:id/permissions/:permission_id", proxyRequest(proxy))

	// Admin delegation
	router.GET("/delegations", proxyRequest(proxy))
	router.POST("/delegations", proxyRequest(proxy))
	router.GET("/delegations/:id", proxyRequest(proxy))
	router.PUT("/delegations/:id", proxyRequest(proxy))
	router.DELETE("/delegations/:id", proxyRequest(proxy))

	// Import/Export operations
	router.POST("/import", proxyRequest(proxy))
	router.GET("/export", proxyRequest(proxy))
	router.POST("/export/schedule", proxyRequest(proxy))

	// Catch-all for other admin routes
	router.Any("/*path", proxyRequest(proxy))
}

// GetAdminURL returns the admin API URL
func GetAdminURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("admin"); err == nil {
		return url
	}
	return "http://localhost:8505"
}

// AdminProxy returns the admin API proxy handler
func AdminProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetAdminURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}
