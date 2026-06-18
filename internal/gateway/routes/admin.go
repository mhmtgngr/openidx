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

	// Proxy every path under this service prefix straight to the backend. All
	// routes share one handler and the groups carry no distinct middleware, so a
	// single catch-all is behaviourally identical to mirroring each endpoint —
	// and it avoids gin's static-vs-wildcard conflict (a catch-all "/*path"
	// cannot coexist with explicit siblings like "/users"). The backend owns
	// auth and routing; the gateway stays a thin pass-through.
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
