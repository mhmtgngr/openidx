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

	// Proxy every path under this service prefix straight to the backend. All
	// routes share one handler and the groups carry no distinct middleware, so a
	// single catch-all is behaviourally identical to mirroring each endpoint —
	// and it avoids gin's static-vs-wildcard conflict (a catch-all "/*path"
	// cannot coexist with explicit siblings like "/users"). The backend owns
	// auth and routing; the gateway stays a thin pass-through.
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
