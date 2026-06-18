// Package routes provides audit service route registration for the gateway
package routes

import (
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

	// Proxy every path under this service prefix straight to the backend. All
	// routes share one handler and the groups carry no distinct middleware, so a
	// single catch-all is behaviourally identical to mirroring each endpoint —
	// and it avoids gin's static-vs-wildcard conflict (a catch-all "/*path"
	// cannot coexist with explicit siblings like "/users"). The backend owns
	// auth and routing; the gateway stays a thin pass-through.
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
