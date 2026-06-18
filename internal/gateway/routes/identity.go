// Package routes provides route registration for the gateway
package routes

import (
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

// ServiceURLProvider provides URLs for backend services
type ServiceURLProvider interface {
	GetServiceURL(serviceName string) (string, error)
}

// RegisterIdentityRoutes registers routes for the identity service
func RegisterIdentityRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("identity")
	if err != nil {
		serviceURL = "http://localhost:8501"
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

// GetIdentityURL returns the identity service URL
func GetIdentityURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("identity"); err == nil {
		return url
	}
	return "http://localhost:8501"
}

// IdentityProxy returns the identity service proxy handler
func IdentityProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetIdentityURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxyRequest(proxy)
}

// proxyRequest creates a gin handler from an httputil.ReverseProxy
func proxyRequest(proxy *httputil.ReverseProxy) gin.HandlerFunc {
	return func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}
