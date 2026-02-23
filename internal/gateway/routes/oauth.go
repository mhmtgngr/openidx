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

	// Public OAuth routes (no authentication)
	router.GET("/.well-known/openid-configuration", proxyRequest(proxy))
	router.GET("/.well-known/jwks.json", proxyRequest(proxy))
	router.GET("/authorize", proxyRequest(proxy))
	router.POST("/token", proxyRequest(proxy))

	// OAuth device authorization flow
	router.POST("/device/code", proxyRequest(proxy))

	// OAuth introspection and revocation (require client authentication)
	router.POST("/introspect", proxyRequest(proxy))
	router.POST("/revoke", proxyRequest(proxy))

	// UserInfo endpoint (requires access token)
	router.GET("/userinfo", proxyRequest(proxy))
	router.POST("/userinfo", proxyRequest(proxy))

	// Session management
	router.POST("/logout", proxyRequest(proxy))

	// Consent management (authenticated)
	router.GET("/consent", proxyRequest(proxy))
	router.POST("/consent", proxyRequest(proxy))
	router.POST("/consent/deny", proxyRequest(proxy))

	// Catch-all for other OAuth routes
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
