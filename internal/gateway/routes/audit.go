// Package routes provides audit service route registration for the gateway
package routes

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterAuditRoutes registers routes for the audit service
func RegisterAuditRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("audit")
	if err != nil {
		serviceURL = "http://localhost:8504"
	}

	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Audit event queries
	router.GET("/events", proxyRequest(proxy))
	router.GET("/events/:id", proxyRequest(proxy))

	// Audit event export
	router.GET("/events/export", proxyRequest(proxy))
	router.POST("/events/export", proxyRequest(proxy))

	// Audit logs (legacy endpoint)
	router.GET("/logs", proxyRequest(proxy))

	// Compliance reports
	router.GET("/reports", proxyRequest(proxy))
	router.POST("/reports", proxyRequest(proxy))
	router.GET("/reports/:id", proxyRequest(proxy))
	router.GET("/reports/:id/download", proxyRequest(proxy))
	router.DELETE("/reports/:id", proxyRequest(proxy))

	// Specific report types
	router.POST("/reports/compliance", proxyRequest(proxy))
	router.POST("/reports/access", proxyRequest(proxy))
	router.POST("/reports/security", proxyRequest(proxy))
	router.POST("/reports/activity", proxyRequest(proxy))

	// Audit statistics
	router.GET("/statistics", proxyRequest(proxy))
	router.GET("/statistics/summary", proxyRequest(proxy))
	router.GET("/statistics/timeline", proxyRequest(proxy))

	// Audit retention policies
	router.GET("/retention-policies", proxyRequest(proxy))
	router.POST("/retention-policies", proxyRequest(proxy))
	router.GET("/retention-policies/:id", proxyRequest(proxy))
	router.PUT("/retention-policies/:id", proxyRequest(proxy))
	router.DELETE("/retention-policies/:id", proxyRequest(proxy))

	// Audit alerts
	router.GET("/alerts", proxyRequest(proxy))
	router.POST("/alerts", proxyRequest(proxy))
	router.GET("/alerts/:id", proxyRequest(proxy))
	router.PUT("/alerts/:id", proxyRequest(proxy))
	router.DELETE("/alerts/:id", proxyRequest(proxy))

	// Audit search
	router.POST("/search", proxyRequest(proxy))

	// Health check for audit service
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "audit"})
	})

	// Catch-all for other audit routes
	router.Any("/*path", proxyRequest(proxy))
}

// GetAuditURL returns the audit service URL
func GetAuditURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("audit"); err == nil {
		return url
	}
	return "http://localhost:8504"
}

// AuditProxy returns the audit service proxy handler
func AuditProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetAuditURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}
