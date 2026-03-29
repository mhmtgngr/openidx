// Package middleware provides security logging middleware for audit service WebSocket connections
package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SecurityEvent represents a security event that should be logged
type SecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Origin      string    `json:"origin"`
	RemoteAddr  string    `json:"remote_addr"`
	RealIP      string    `json:"real_ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	RequestURI  string    `json:"request_uri,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	ActionTaken string    `json:"action_taken"`
}

// WebSocketSecurityLogger logs security events related to WebSocket connections
type WebSocketSecurityLogger struct {
	logger *zap.Logger
}

// NewWebSocketSecurityLogger creates a new WebSocket security logger
func NewWebSocketSecurityLogger(logger *zap.Logger) *WebSocketSecurityLogger {
	return &WebSocketSecurityLogger{
		logger: logger.Named("websocket-security"),
	}
}

// LogRejectedConnection logs a rejected WebSocket connection attempt
func (wsl *WebSocketSecurityLogger) LogRejectedConnection(event *SecurityEvent) {
	if event == nil {
		return
	}

	wsl.logger.Warn("WebSocket connection rejected",
		zap.String("origin", event.Origin),
		zap.String("remote_addr", event.RemoteAddr),
		zap.String("real_ip", event.RealIP),
		zap.String("user_agent", event.UserAgent),
		zap.String("request_uri", event.RequestURI),
		zap.String("reason", event.Reason),
		zap.String("action_taken", event.ActionTaken),
	)
}

// LogAcceptedConnection logs an accepted WebSocket connection
func (wsl *WebSocketSecurityLogger) LogAcceptedConnection(origin, remoteAddr, userAgent string) {
	wsl.logger.Info("WebSocket connection accepted",
		zap.String("origin", origin),
		zap.String("remote_addr", remoteAddr),
		zap.String("user_agent", userAgent),
	)
}

// LogSuspiciousActivity logs suspicious WebSocket-related activity
func (wsl *WebSocketSecurityLogger) LogSuspiciousActivity(event *SecurityEvent) {
	wsl.logger.Error("Suspicious WebSocket activity detected",
		zap.String("event_type", event.EventType),
		zap.String("origin", event.Origin),
		zap.String("remote_addr", event.RemoteAddr),
		zap.String("real_ip", event.RealIP),
		zap.String("reason", event.Reason),
	)
}

// ExtractRealIP extracts the real client IP from the request headers
func ExtractRealIP(r *http.Request) string {
	// Check X-Forwarded-For header (typically set by reverse proxies)
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Take the first IP from the chain
		if idx := strings.Index(forwardedFor, ","); idx > 0 {
			return strings.TrimSpace(forwardedFor[:idx])
		}
		return strings.TrimSpace(forwardedFor)
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Check CF-Connecting-IP header (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		// Remove port if present
		if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
			return r.RemoteAddr[:idx]
		}
		return r.RemoteAddr
	}

	return "unknown"
}

// SecurityLoggingMiddleware creates Gin middleware for WebSocket security logging
func SecurityLoggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only log WebSocket upgrade requests
		if !isWebSocketUpgrade(c.Request) {
			c.Next()
			return
		}

		// Extract information for security logging
		origin := c.Request.Header.Get("Origin")
		realIP := ExtractRealIP(c.Request)

		// Store in context for later use
		c.Set("ws_origin", origin)
		c.Set("ws_real_ip", realIP)

		c.Next()
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// RejectOriginHandler creates a handler that rejects requests with disallowed origins
func RejectOriginHandler(logger *zap.Logger, allowedOrigins []string) gin.HandlerFunc {
	securityLogger := NewWebSocketSecurityLogger(logger)

	return func(c *gin.Context) {
		if !isWebSocketUpgrade(c.Request) {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		realIP := ExtractRealIP(c.Request)

		// Skip check if no origin (non-browser request)
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed
		allowed := false
		normalizedOrigin := strings.ToLower(strings.TrimSpace(origin))

		for _, allowedOrigin := range allowedOrigins {
			allowedOrigin = strings.ToLower(strings.TrimSpace(allowedOrigin))

			// Wildcard match
			if allowedOrigin == "*" {
				allowed = true
				break
			}

			// Exact match
			if normalizedOrigin == allowedOrigin {
				allowed = true
				break
			}

			// Wildcard subdomain
			if strings.HasPrefix(allowedOrigin, "*.") {
				domain := strings.TrimPrefix(allowedOrigin, "*.")
				// Only match subdomains, not the bare domain
				if strings.HasSuffix(normalizedOrigin, "."+domain) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			// Log the rejected connection attempt
			securityLogger.LogRejectedConnection(&SecurityEvent{
				Timestamp:   time.Now().UTC(),
				EventType:   "origin_rejected",
				Origin:      origin,
				RemoteAddr:  c.Request.RemoteAddr,
				RealIP:      realIP,
				UserAgent:   c.Request.UserAgent(),
				RequestURI:  c.Request.RequestURI,
				Reason:      "origin not in allowed list",
				ActionTaken: "connection_rejected",
			})

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "origin_not_allowed",
				"message": "WebSocket connections from your origin are not allowed",
			})
			return
		}

		c.Next()
	}
}

// RapidConnectionTracker tracks rapid connection attempts from the same IP
type RapidConnectionTracker struct {
	logger        *zap.Logger
	attempts      map[string][]time.Time
	maxAttempts   int
	windowSeconds int
}

// NewRapidConnectionTracker creates a new rapid connection tracker
func NewRapidConnectionTracker(logger *zap.Logger, maxAttempts, windowSeconds int) *RapidConnectionTracker {
	return &RapidConnectionTracker{
		logger:        logger.Named("rapid-connection-tracker"),
		attempts:      make(map[string][]time.Time),
		maxAttempts:   maxAttempts,
		windowSeconds: windowSeconds,
	}
}

// CheckAndRecord checks if the IP has exceeded the rate limit and records the attempt
func (rct *RapidConnectionTracker) CheckAndRecord(ip string) (allowed bool, count int) {
	now := time.Now()
	cutoff := now.Add(-time.Duration(rct.windowSeconds) * time.Second)

	// Clean up old attempts and count recent ones
	recentAttempts := make([]time.Time, 0)
	for _, attempt := range rct.attempts[ip] {
		if attempt.After(cutoff) {
			recentAttempts = append(recentAttempts, attempt)
		}
	}

	rct.attempts[ip] = recentAttempts
	count = len(recentAttempts)

	if count >= rct.maxAttempts {
		rct.logger.Warn("Rapid WebSocket connection attempts detected",
			zap.String("ip", ip),
			zap.Int("attempt_count", count),
			zap.Int("max_allowed", rct.maxAttempts),
			zap.Int("window_seconds", rct.windowSeconds))
		return false, count
	}

	// Record this attempt
	rct.attempts[ip] = append(recentAttempts, now)
	return true, count
}

// CleanupOldEntries removes entries older than the window
func (rct *RapidConnectionTracker) CleanupOldEntries() {
	now := time.Now()
	cutoff := now.Add(-time.Duration(rct.windowSeconds) * time.Second)

	for ip, attempts := range rct.attempts {
		recentAttempts := make([]time.Time, 0)
		for _, attempt := range attempts {
			if attempt.After(cutoff) {
				recentAttempts = append(recentAttempts, attempt)
			}
		}
		if len(recentAttempts) == 0 {
			delete(rct.attempts, ip)
		} else {
			rct.attempts[ip] = recentAttempts
		}
	}
}
