// Package routes provides governance service route registration for the gateway
package routes

import (
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterGovernanceRoutes registers routes for the governance service
func RegisterGovernanceRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("governance")
	if err != nil {
		serviceURL = "http://localhost:8503"
	}

	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Access reviews
	router.GET("/reviews", proxyRequest(proxy))
	router.POST("/reviews", proxyRequest(proxy))
	router.GET("/reviews/:id", proxyRequest(proxy))
	router.PUT("/reviews/:id", proxyRequest(proxy))
	router.DELETE("/reviews/:id", proxyRequest(proxy))

	// Access review decisions
	router.POST("/reviews/:id/items/:item_id/decision", proxyRequest(proxy))
	router.POST("/reviews/:id/approve", proxyRequest(proxy))
	router.POST("/reviews/:id/deny", proxyRequest(proxy))
	router.POST("/reviews/:id/escalate", proxyRequest(proxy))

	// Access review bulk operations
	router.POST("/reviews/:id/bulk-decide", proxyRequest(proxy))

	// Policies
	router.GET("/policies", proxyRequest(proxy))
	router.POST("/policies", proxyRequest(proxy))
	router.GET("/policies/:id", proxyRequest(proxy))
	router.PUT("/policies/:id", proxyRequest(proxy))
	router.DELETE("/policies/:id", proxyRequest(proxy))

	// Policy assignments
	router.GET("/policies/:id/assignments", proxyRequest(proxy))
	router.POST("/policies/:id/assignments", proxyRequest(proxy))
	router.DELETE("/policies/:id/assignments/:assignment_id", proxyRequest(proxy))

	// Certifications
	router.GET("/certifications", proxyRequest(proxy))
	router.POST("/certifications", proxyRequest(proxy))
	router.GET("/certifications/:id", proxyRequest(proxy))
	router.PUT("/certifications/:id", proxyRequest(proxy))

	// Certification tasks
	router.GET("/certifications/:id/tasks", proxyRequest(proxy))
	router.POST("/certifications/:id/tasks/:task_id/complete", proxyRequest(proxy))

	// Role requests
	router.GET("/role-requests", proxyRequest(proxy))
	router.POST("/role-requests", proxyRequest(proxy))
	router.GET("/role-requests/:id", proxyRequest(proxy))
	router.POST("/role-requests/:id/approve", proxyRequest(proxy))
	router.POST("/role-requests/:id/deny", proxyRequest(proxy))

	// Attestations
	router.GET("/attestations", proxyRequest(proxy))
	router.POST("/attestations", proxyRequest(proxy))
	router.GET("/attestations/:id", proxyRequest(proxy))
	router.POST("/attestations/:id/respond", proxyRequest(proxy))

	// Governance reports
	router.GET("/reports/access-review", proxyRequest(proxy))
	router.GET("/reports/certification-status", proxyRequest(proxy))
	router.GET("/reports/policy-compliance", proxyRequest(proxy))

	// Catch-all for other governance routes
	router.Any("/*path", proxyRequest(proxy))
}

// GetGovernanceURL returns the governance service URL
func GetGovernanceURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("governance"); err == nil {
		return url
	}
	return "http://localhost:8503"
}

// GovernanceProxy returns the governance service proxy handler
func GovernanceProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetGovernanceURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}
