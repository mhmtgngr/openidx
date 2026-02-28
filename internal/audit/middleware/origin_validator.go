// Package middleware provides reusable origin validation middleware for audit service
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/audit"
	"go.uber.org/zap"
)

// OriginValidationConfig holds configuration for origin validation middleware
type OriginValidationConfig struct {
	AllowedOrigins     []string
	EnableLogging      bool
	RejectOnFailure    bool
	AllowEmptyOrigin   bool // Allow requests without Origin header (non-browser clients)
	ProductionMode     bool
}

// DefaultOriginValidationConfig returns default configuration for development
func DefaultOriginValidationConfig() *OriginValidationConfig {
	return &OriginValidationConfig{
		AllowedOrigins:   []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
			"http://localhost:8080",
		},
		EnableLogging:    true,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true,
		ProductionMode:   false,
	}
}

// ProductionOriginValidationConfig returns secure configuration for production
func ProductionOriginValidationConfig(allowedOrigins []string) *OriginValidationConfig {
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{} // Empty means same-origin only
	}
	return &OriginValidationConfig{
		AllowedOrigins:   allowedOrigins,
		EnableLogging:    true,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true, // Still allow non-browser clients
		ProductionMode:   true,
	}
}

// OriginValidatorMiddleware creates Gin middleware for validating request origins
func OriginValidatorMiddleware(logger *zap.Logger, config *OriginValidationConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultOriginValidationConfig()
	}

	securityLogger := NewWebSocketSecurityLogger(logger)

	// Pre-normalize allowed origins for efficiency
	normalizedOrigins := make([]string, len(config.AllowedOrigins))
	for i, origin := range config.AllowedOrigins {
		normalizedOrigins[i] = audit.NormalizeOrigin(origin)
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		realIP := ExtractRealIP(c.Request)

		// Handle empty origin (non-browser requests)
		if origin == "" {
			if config.AllowEmptyOrigin {
				if config.EnableLogging {
					securityLogger.LogAcceptedConnection("", realIP, c.Request.UserAgent())
				}
				c.Next()
				return
			}
			// Reject if empty origins are not allowed
			if config.EnableLogging {
				securityLogger.LogRejectedConnection(&SecurityEvent{
					EventType:   "empty_origin_rejected",
					Origin:      origin,
					RemoteAddr:  c.Request.RemoteAddr,
					RealIP:      realIP,
					UserAgent:   c.Request.UserAgent(),
					RequestURI:  c.Request.RequestURI,
					Reason:      "empty Origin header not allowed",
					ActionTaken: "request_rejected",
				})
			}
			if config.RejectOnFailure {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "origin_required",
					"message": "Requests must include an Origin header",
				})
				return
			}
		}

		// Normalize the incoming origin
		normalizedOrigin := audit.NormalizeOrigin(origin)

		// Check against allowed origins
		allowed := false
		matchedPattern := ""

		for _, allowedOrigin := range normalizedOrigins {
			// Wildcard allows all
			if allowedOrigin == "*" {
				if config.ProductionMode {
					securityLogger.LogSuspiciousActivity(&SecurityEvent{
						EventType:   "wildcard_in_production",
						Origin:      origin,
						RemoteAddr:  c.Request.RemoteAddr,
						RealIP:      realIP,
						Reason:      "wildcard origin should not be used in production",
						ActionTaken: "logged_for_review",
					})
				}
				allowed = true
				matchedPattern = "*"
				break
			}

			// Exact match
			if normalizedOrigin == allowedOrigin {
				allowed = true
				matchedPattern = allowedOrigin
				break
			}

			// Wildcard subdomain (e.g., *.example.com)
			// Note: Only matches subdomains, not the bare domain
			if strings.HasPrefix(allowedOrigin, "*.") {
				domain := strings.TrimPrefix(allowedOrigin, "*.")
				if strings.HasSuffix(normalizedOrigin, "."+domain) {
					allowed = true
					matchedPattern = allowedOrigin
					break
				}
			}
		}

		// Same-origin check when no explicit whitelist is configured
		if !allowed && len(config.AllowedOrigins) == 0 {
			requestHost := c.Request.Host
			if requestHost == "" {
				requestHost = c.Request.Header.Get("Host")
			}
			normalizedHost := strings.ToLower(requestHost)
			normalizedHost = strings.TrimSuffix(normalizedHost, ":80")
			normalizedHost = strings.TrimSuffix(normalizedHost, ":443")

			// Construct expected origin
			var expectedOrigin string
			if c.Request.TLS != nil || strings.HasPrefix(normalizedOrigin, "https://") {
				expectedOrigin = "https://" + normalizedHost
			} else {
				expectedOrigin = "http://" + normalizedHost
			}
			expectedOrigin = audit.NormalizeOrigin(expectedOrigin)

			if normalizedOrigin == expectedOrigin {
				allowed = true
				matchedPattern = "same-origin"
			}
		}

		if !allowed {
			// Log the rejected connection attempt
			if config.EnableLogging {
				securityLogger.LogRejectedConnection(&SecurityEvent{
					EventType:   "origin_not_allowed",
					Origin:      origin,
					RemoteAddr:  c.Request.RemoteAddr,
					RealIP:      realIP,
					UserAgent:   c.Request.UserAgent(),
					RequestURI:  c.Request.RequestURI,
					Reason:      fmt.Sprintf("origin not in allowed list (matched against %d patterns)", len(config.AllowedOrigins)),
					ActionTaken: "request_rejected",
				})
			}
			if config.RejectOnFailure {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "origin_not_allowed",
					"message": "Requests from your origin are not allowed",
				})
				return
			}
			// Mark as not validated and continue
			c.Set("origin_validated", false)
			c.Next()
			return
		}

		// Log successful validation
		if config.EnableLogging {
			securityLogger.LogAcceptedConnection(origin, realIP, c.Request.UserAgent())
		}

		// Store validation result in context for downstream handlers
		c.Set("origin_validated", true)
		c.Set("origin", origin)
		c.Set("matched_pattern", matchedPattern)

		c.Next()
	}
}

// WebSocketOriginValidator creates a gorilla/websocket compatible CheckOrigin function
// from the middleware configuration
func WebSocketOriginValidator(logger *zap.Logger, config *OriginValidationConfig) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		// Allow empty origin if configured (non-browser clients)
		if origin == "" {
			return config.AllowEmptyOrigin
		}

		// Use the audit package's IsOriginAllowed function
		if len(config.AllowedOrigins) == 0 {
			// Same-origin policy
			requestHost := r.Host
			if requestHost == "" {
				requestHost = r.Header.Get("Host")
			}
			normalizedHost := strings.ToLower(requestHost)
			normalizedHost = strings.TrimSuffix(normalizedHost, ":80")
			normalizedHost = strings.TrimSuffix(normalizedHost, ":443")

			normalizedOrigin := audit.NormalizeOrigin(origin)

			var expectedOrigin string
			if r.TLS != nil || strings.HasPrefix(normalizedOrigin, "https://") {
				expectedOrigin = "https://" + normalizedHost
			} else {
				expectedOrigin = "http://" + normalizedHost
			}
			expectedOrigin = audit.NormalizeOrigin(expectedOrigin)

			return normalizedOrigin == expectedOrigin
		}

		// Check against whitelist
		return audit.IsOriginAllowed(origin, config.AllowedOrigins)
	}
}

// GetOriginFromContext extracts the validated origin from the Gin context
func GetOriginFromContext(c *gin.Context) string {
	if origin, exists := c.Get("origin"); exists {
		if s, ok := origin.(string); ok {
			return s
		}
	}
	return ""
}

// IsOriginValidated checks if the request's origin was validated
func IsOriginValidated(c *gin.Context) bool {
	if validated, exists := c.Get("origin_validated"); exists {
		if b, ok := validated.(bool); ok {
			return b
		}
	}
	return false
}
