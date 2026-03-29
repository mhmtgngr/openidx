// Package middleware provides WebSocket origin validation middleware for admin API
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// WebSocketOriginConfig holds WebSocket origin validation configuration
type WebSocketOriginConfig struct {
	AllowedOrigins []string
	EnableLogging  bool
}

// WebSocketOriginValidator provides origin validation for admin API WebSocket endpoints
type WebSocketOriginValidator struct {
	logger *zap.Logger
	config *WebSocketOriginConfig
}

// NewWebSocketOriginValidator creates a new WebSocket origin validator for admin API
func NewWebSocketOriginValidator(logger *zap.Logger, config *WebSocketOriginConfig) *WebSocketOriginValidator {
	if config == nil {
		config = &WebSocketOriginConfig{
			AllowedOrigins: []string{}, // Same-origin only by default
			EnableLogging:  true,
		}
	}
	return &WebSocketOriginValidator{
		logger: logger.Named("admin-websocket-validator"),
		config: config,
	}
}

// CheckOrigin validates the Origin header for WebSocket connections
func (wv *WebSocketOriginValidator) CheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")

	// Allow non-browser requests (no Origin header)
	if origin == "" {
		if wv.config.EnableLogging {
			wv.logger.Debug("Admin WebSocket allowed (no Origin header)",
				zap.String("remote_addr", r.RemoteAddr))
		}
		return true
	}

	// Normalize origin
	normalized := strings.ToLower(strings.TrimSpace(origin))

	// Check against allowed origins
	for _, allowed := range wv.config.AllowedOrigins {
		allowed = strings.ToLower(strings.TrimSpace(allowed))

		// Wildcard allows all (use with caution)
		if allowed == "*" {
			if wv.config.EnableLogging {
				wv.logger.Warn("Admin WebSocket wildcard origin allowed",
					zap.String("origin", origin),
					zap.String("remote_addr", r.RemoteAddr))
			}
			return true
		}

		// Exact match
		if normalized == allowed {
			if wv.config.EnableLogging {
				wv.logger.Info("Admin WebSocket connection allowed",
					zap.String("origin", origin),
					zap.String("remote_addr", r.RemoteAddr))
			}
			return true
		}

		// Wildcard subdomain
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			// Note: Admin API allows both subdomains and bare domain for wildcard patterns
			if strings.HasSuffix(normalized, "."+domain) || normalized == domain {
				if wv.config.EnableLogging {
					wv.logger.Info("Admin WebSocket connection allowed (subdomain match)",
						zap.String("origin", origin),
						zap.String("pattern", allowed),
						zap.String("remote_addr", r.RemoteAddr))
				}
				return true
			}
		}
	}

	// Origin not allowed
	if wv.config.EnableLogging {
		wv.logger.Warn("Admin WebSocket connection rejected",
			zap.String("origin", origin),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.Int("allowed_count", len(wv.config.AllowedOrigins)))
	}

	return false
}

// AdminWebSocketOriginMiddleware returns Gin middleware for validating WebSocket origins
func AdminWebSocketOriginMiddleware(logger *zap.Logger, allowedOrigins []string) gin.HandlerFunc {
	validator := NewWebSocketOriginValidator(logger, &WebSocketOriginConfig{
		AllowedOrigins: allowedOrigins,
		EnableLogging:  true,
	})

	return func(c *gin.Context) {
		// Only check WebSocket upgrade requests
		if !isWebSocketUpgradeRequest(c.Request) {
			c.Next()
			return
		}

		if !validator.CheckOrigin(c.Request) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "websocket_origin_not_allowed",
				"message": "WebSocket connections from your origin are not allowed for admin access",
			})
			return
		}

		c.Next()
	}
}

// isWebSocketUpgradeRequest checks if the request is a WebSocket upgrade
func isWebSocketUpgradeRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// UpdateAllowedOrigins updates the allowed origins list
func (wv *WebSocketOriginValidator) UpdateAllowedOrigins(origins []string) {
	wv.config.AllowedOrigins = origins
	wv.logger.Info("Admin WebSocket origin validator updated",
		zap.Int("origin_count", len(origins)))
}

// GetAllowedOrigins returns the current allowed origins
func (wv *WebSocketOriginValidator) GetAllowedOrigins() []string {
	return wv.config.AllowedOrigins
}

// AdminWebSocketSecurityEvent represents a security event for admin WebSocket
type AdminWebSocketSecurityEvent struct {
	Timestamp  string `json:"timestamp"`
	EventType  string `json:"event_type"`
	Origin     string `json:"origin,omitempty"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// LogAdminWebSocketSecurityEvent logs a security event for admin WebSocket
func LogAdminWebSocketSecurityEvent(logger *zap.Logger, event *AdminWebSocketSecurityEvent) {
	logger.Warn("Admin WebSocket security event",
		zap.String("event_type", event.EventType),
		zap.String("origin", event.Origin),
		zap.String("remote_addr", event.RemoteAddr),
		zap.String("user_agent", event.UserAgent),
		zap.String("reason", event.Reason),
	)
}
