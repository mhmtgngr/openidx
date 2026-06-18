// Package routes provides OAuth service route registration for the gateway
package routes

import (
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// RegisterOAuthRoutes registers routes for the OAuth service
func RegisterOAuthRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("oauth")
	if err != nil {
		serviceURL = "http://localhost:8502"
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

// GetOAuthURL returns the OAuth service URL
func GetOAuthURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("oauth"); err == nil {
		return url
	}
	return "http://localhost:8502"
}

// OAuthProxy returns the OAuth service proxy handler
func OAuthProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetOAuthURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}
