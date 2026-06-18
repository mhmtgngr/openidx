// Package routes provides risk service route registration for the gateway
package routes

import (
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

	// Proxy every path under this service prefix straight to the backend. All
	// routes share one handler and the groups carry no distinct middleware, so a
	// single catch-all is behaviourally identical to mirroring each endpoint —
	// and it avoids gin's static-vs-wildcard conflict (a catch-all "/*path"
	// cannot coexist with explicit siblings like "/users"). The backend owns
	// auth and routing; the gateway stays a thin pass-through.
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
