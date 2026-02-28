// Package audit provides WebSocket origin validation for audit event streaming
package audit

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// OriginValidator provides origin validation for WebSocket connections
type OriginValidator struct {
	logger        *zap.Logger
	allowedOrigins []string
	enableLogging bool
}

// NewOriginValidator creates a new origin validator
func NewOriginValidator(logger *zap.Logger, allowedOrigins []string, enableLogging bool) *OriginValidator {
	return &OriginValidator{
		logger:        logger,
		allowedOrigins: allowedOrigins,
		enableLogging: enableLogging,
	}
}

// CheckOrigin is a gorilla/websocket compatible CheckOrigin function
// It validates the Origin header against the allowed origins list
func (ov *OriginValidator) CheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")

	// If no Origin header is present, this is likely a non-browser request
	// (e.g., health check, CLI tool, another service)
	if origin == "" {
		// Allow non-browser requests
		if ov.enableLogging {
			ov.logger.Debug("WebSocket connection allowed (no Origin header)",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()))
		}
		return true
	}

	// Normalize the origin for comparison
	normalized := NormalizeOrigin(origin)

	// If no allowed origins are configured, enforce same-origin policy
	if len(ov.allowedOrigins) == 0 {
		// Extract host from request
		requestHost := r.Host
		if requestHost == "" {
			// Fallback to Host header
			requestHost = r.Header.Get("Host")
		}
		normalizedHost := strings.ToLower(requestHost)
		// Remove default port
		normalizedHost = strings.TrimSuffix(normalizedHost, ":80")
		normalizedHost = strings.TrimSuffix(normalizedHost, ":443")

		// Check if origin matches the request host (same-origin)
		if strings.HasSuffix(normalized, "//"+normalizedHost) {
			if ov.enableLogging {
				ov.logger.Info("WebSocket connection allowed (same-origin)",
					zap.String("origin", origin),
					zap.String("host", requestHost),
					zap.String("remote_addr", r.RemoteAddr))
			}
			return true
		}

		// Reject cross-origin requests when no whitelist is configured
		ov.logRejectedConnection(r, origin, "same-origin policy violation")
		return false
	}

	// Check against allowed origins list
	for _, allowed := range ov.allowedOrigins {
		allowed = NormalizeOrigin(allowed)

		// Wildcard allows all
		if allowed == "*" {
			if ov.enableLogging {
				ov.logger.Warn("WebSocket wildcard origin allowed (SECURITY RISK)",
					zap.String("origin", origin),
					zap.String("remote_addr", r.RemoteAddr))
			}
			return true
		}

		// Exact match
		if normalized == allowed {
			if ov.enableLogging {
				ov.logger.Info("WebSocket connection allowed (exact match)",
					zap.String("origin", origin),
					zap.String("remote_addr", r.RemoteAddr))
			}
			return true
		}

		// Wildcard subdomain (e.g., *.example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(normalized, "."+domain) || normalized == domain {
				if ov.enableLogging {
					ov.logger.Info("WebSocket connection allowed (subdomain match)",
						zap.String("origin", origin),
						zap.String("pattern", allowed),
						zap.String("remote_addr", r.RemoteAddr))
				}
				return true
			}
		}
	}

	// Origin not found in allowed list
	ov.logRejectedConnection(r, origin, "origin not in whitelist")
	return false
}

// logRejectedConnection logs security-relevant information about rejected connections
func (ov *OriginValidator) logRejectedConnection(r *http.Request, origin, reason string) {
	if !ov.enableLogging {
		return
	}

	// Extract real IP from X-Forwarded-For or X-Real-IP if present
	realIP := r.RemoteAddr
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Take the first IP from the forwarded chain
		if idx := strings.Index(forwardedFor, ","); idx > 0 {
			realIP = forwardedFor[:idx]
		} else {
			realIP = forwardedFor
		}
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		realIP = realIP
	}

	ov.logger.Warn("WebSocket connection rejected",
		zap.String("origin", origin),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("real_ip", realIP),
		zap.String("user_agent", r.UserAgent()),
		zap.String("reason", reason),
		zap.String("request_uri", r.RequestURI),
	)
}

// GetAllowedOrigins returns the current allowed origins list
func (ov *OriginValidator) GetAllowedOrigins() []string {
	return ov.allowedOrigins
}

// UpdateAllowedOrigins updates the allowed origins list
func (ov *OriginValidator) UpdateAllowedOrigins(origins []string) {
	ov.allowedOrigins = origins
	ov.logger.Info("WebSocket origin validator updated",
		zap.Int("origin_count", len(origins)))
}

// IsWildcardAllowed returns true if wildcard origins are allowed
func (ov *OriginValidator) IsWildcardAllowed() bool {
	for _, origin := range ov.allowedOrigins {
		if origin == "*" || origin == "*." {
			return true
		}
	}
	return false
}
