// Package routes provides route registration for the gateway
package routes

import (
	"net/http"
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

	// Public routes (no authentication required)
	public := router.Group("")
	{
		// Health check
		public.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "identity"})
		})

		// Login endpoints
		public.POST("/login", proxyRequest(proxy))
		public.POST("/logout", proxyRequest(proxy))
		public.POST("/register", proxyRequest(proxy))

		// Password reset
		public.POST("/password/reset/request", proxyRequest(proxy))
		public.POST("/password/reset/confirm", proxyRequest(proxy))

		// MFA verification (after initial auth)
		public.POST("/mfa/verify", proxyRequest(proxy))
		public.POST("/mfa/totp/verify", proxyRequest(proxy))
	}

	// Protected routes (require authentication)
	protected := router.Group("")
	{
		// User management
		protected.GET("/users", proxyRequest(proxy))
		protected.GET("/users/:id", proxyRequest(proxy))
		protected.POST("/users", proxyRequest(proxy))
		protected.PUT("/users/:id", proxyRequest(proxy))
		protected.DELETE("/users/:id", proxyRequest(proxy))

		// User sessions
		protected.GET("/users/:id/sessions", proxyRequest(proxy))
		protected.DELETE("/users/:id/sessions/:session_id", proxyRequest(proxy))

		// MFA management
		protected.GET("/mfa/totp/setup", proxyRequest(proxy))
		protected.POST("/mfa/totp/enable", proxyRequest(proxy))
		protected.DELETE("/mfa/totp/disable", proxyRequest(proxy))
		protected.GET("/mfa/recovery-codes", proxyRequest(proxy))
		protected.POST("/mfa/recovery-codes/regenerate", proxyRequest(proxy))

		// Profile management
		protected.GET("/profile", proxyRequest(proxy))
		protected.PUT("/profile", proxyRequest(proxy))
		protected.POST("/profile/password", proxyRequest(proxy))

		// Role assignments
		protected.GET("/users/:id/roles", proxyRequest(proxy))
		protected.POST("/users/:id/roles", proxyRequest(proxy))
		protected.DELETE("/users/:id/roles/:role_id", proxyRequest(proxy))
	}

	// Catch-all for other identity routes
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
