// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds configuration for CORS middleware
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins. Use "*" to allow all.
	AllowedOrigins []string
	// AllowedMethods specifies the allowed HTTP methods
	AllowedMethods []string
	// AllowedHeaders specifies the allowed headers
	AllowedHeaders []string
	// ExposedHeaders specifies headers exposed to the browser
	ExposedHeaders []string
	// AllowCredentials indicates whether credentials can be included
	AllowCredentials bool
	// MaxAge specifies how long the results of a preflight request can be cached
	MaxAge int
}

// DefaultCORSConfig returns the default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "X-Total-Count"},
		AllowCredentials: false,
		MaxAge:           86400, // 24 hours
	}
}

// CORSConfigFromEnv creates CORS config from ALLOWED_ORIGINS environment variable
// Origins should be comma-separated. Example: "https://example.com,https://app.example.com"
func CORSConfigFromEnv() CORSConfig {
	cfg := DefaultCORSConfig()

	originsEnv := os.Getenv("ALLOWED_ORIGINS")
	if originsEnv != "" {
		origins := strings.Split(originsEnv, ",")
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		cfg.AllowedOrigins = origins
	}

	return cfg
}

// CORS returns a middleware that handles CORS headers with configurable origins.
// It reads from ALLOWED_ORIGINS env var by default.
// Supports credentials, preflight caching (24h default), and proper Vary header handling.
func CORS(cfg CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow requests with no Origin header (non-browser requests like health checks, mobile apps, etc.)
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed
		allowed := false
		allowAllOrigins := false

		for _, allowedOrigin := range cfg.AllowedOrigins {
			if allowedOrigin == "*" {
				allowAllOrigins = true
				allowed = true
				break
			}
			if allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if !allowed {
			// Origin not in whitelist
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Set Access-Control-Allow-Origin
		if allowAllOrigins {
			if cfg.AllowCredentials {
				// When credentials are enabled, "*" is not valid - use the actual origin
				c.Header("Access-Control-Allow-Origin", origin)
			} else {
				c.Header("Access-Control-Allow-Origin", "*")
			}
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		// Always add Vary: Origin for proper caching
		if !allowAllOrigins || cfg.AllowCredentials {
			c.Header("Vary", "Origin")
		}

		// Set Access-Control-Allow-Credentials
		if cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Set Access-Control-Allow-Methods
		if len(cfg.AllowedMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
		}

		// Set Access-Control-Allow-Headers
		if len(cfg.AllowedHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
		}

		// Set Access-Control-Expose-Headers
		if len(cfg.ExposedHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
		}

		// Set Access-Control-Max-Age for preflight caching
		if cfg.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", string(rune(cfg.MaxAge)))
		}

		// Handle preflight request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SimpleCORS returns a CORS middleware with default configuration
func SimpleCORS() gin.HandlerFunc {
	return CORS(DefaultCORSConfig())
}

// CORSWithOrigins returns a CORS middleware that allows specific origins
func CORSWithOrigins(origins ...string) gin.HandlerFunc {
	cfg := DefaultCORSConfig()
	cfg.AllowedOrigins = origins
	return CORS(cfg)
}
