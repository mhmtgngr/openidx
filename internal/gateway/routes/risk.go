// Package routes provides risk service route registration for the gateway
package routes

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterRiskRoutes registers routes for the risk service
func RegisterRiskRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("risk")
	if err != nil {
		serviceURL = "http://localhost:8506"
	}

	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Risk scoring
	router.POST("/score", proxyRequest(proxy))
	router.GET("/score/:user_id", proxyRequest(proxy))

	// Anomaly detection
	router.POST("/anomalies/check", proxyRequest(proxy))
	router.GET("/anomalies", proxyRequest(proxy))
	router.GET("/anomalies/:id", proxyRequest(proxy))

	// Threat intelligence
	router.GET("/threats/ip/:ip_address", proxyRequest(proxy))
	router.POST("/threats/check-ip", proxyRequest(proxy))

	// Risk policies
	router.GET("/policies", proxyRequest(proxy))
	router.POST("/policies", proxyRequest(proxy))
	router.GET("/policies/:id", proxyRequest(proxy))
	router.PUT("/policies/:id", proxyRequest(proxy))
	router.DELETE("/policies/:id", proxyRequest(proxy))

	// Risk events
	router.GET("/events", proxyRequest(proxy))
	router.GET("/events/:id", proxyRequest(proxy))
	router.PUT("/events/:id", proxyRequest(proxy))

	// Risk alerts
	router.GET("/alerts", proxyRequest(proxy))
	router.GET("/alerts/:id", proxyRequest(proxy))
	router.POST("/alerts/:id/acknowledge", proxyRequest(proxy))
	router.POST("/alerts/:id/dismiss", proxyRequest(proxy))

	// User risk profile
	router.GET("/profiles/:user_id", proxyRequest(proxy))
	router.PUT("/profiles/:user_id", proxyRequest(proxy))

	// Risk statistics
	router.GET("/statistics", proxyRequest(proxy))
	router.GET("/statistics/summary", proxyRequest(proxy))

	// Health check for risk service
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "risk"})
	})

	// Catch-all for other risk routes
	router.Any("/*path", proxyRequest(proxy))
}

// GetRiskURL returns the risk service URL
func GetRiskURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("risk"); err == nil {
		return url
	}
	return "http://localhost:8506"
}

// RiskProxy returns the risk service proxy handler
func RiskProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetRiskURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}
