// Package audit provides audit service configuration
package audit

import (
	"strings"

	"github.com/openidx/openidx/internal/common/config"
)

// StreamConfig holds WebSocket streamer configuration
type StreamConfig struct {
	// AllowedOrigins is a list of allowed WebSocket origins.
	// Empty slice means same-origin policy (only connections from the same host).
	// Wildcard "*" allows any origin (NEVER use in production).
	AllowedOrigins []string

	// EnableSecurityLogging enables logging for rejected WebSocket connections
	EnableSecurityLogging bool

	// MaxMessageSize limits the size of WebSocket messages in bytes
	MaxMessageSize int

	// WriteTimeout is the timeout for writing messages to the WebSocket
	WriteTimeout int

	// ReadTimeout is the timeout for reading messages from the WebSocket
	ReadTimeout int

	// PingInterval is the interval for sending ping messages
	PingInterval int

	// PongTimeout is the timeout for receiving a pong response
	PongTimeout int
}

// DefaultStreamConfig returns the default streamer configuration
func DefaultStreamConfig() *StreamConfig {
	return &StreamConfig{
		AllowedOrigins:        nil, // Same-origin by default
		EnableSecurityLogging: true,
		MaxMessageSize:        1024 * 64, // 64KB
		WriteTimeout:          10,
		ReadTimeout:           60,
		PingInterval:          30,
		PongTimeout:           60,
	}
}

// StreamConfigFromAppConfig creates a StreamConfig from the application config
func StreamConfigFromAppConfig(cfg *config.Config) *StreamConfig {
	sc := DefaultStreamConfig()

	// Parse allowed origins from config
	origins := cfg.GetAuditStreamAllowedOrigins()
	if len(origins) > 0 {
		sc.AllowedOrigins = origins
	}

	return sc
}

// NormalizeOrigin normalizes an origin URL for comparison
func NormalizeOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	origin = strings.ToLower(origin)

	// Remove default ports for http and https
	if strings.HasPrefix(origin, "http://") {
		origin = strings.TrimSuffix(origin, ":80")
	} else if strings.HasPrefix(origin, "https://") {
		origin = strings.TrimSuffix(origin, ":443")
	}

	return origin
}

// IsOriginAllowed checks if an origin is allowed based on the configured list
func IsOriginAllowed(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		// Same-origin policy: only allow if origin is empty (non-browser)
		// This will be checked differently in the WebSocket handler
		return false
	}

	normalized := NormalizeOrigin(origin)

	for _, allowed := range allowedOrigins {
		allowed = NormalizeOrigin(allowed)

		// Wildcard allows all
		if allowed == "*" {
			return true
		}

		// Exact match
		if normalized == allowed {
			return true
		}

		// Wildcard subdomain (e.g., *.example.com)
		// Note: This only matches subdomains, not the bare domain
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(normalized, "."+domain) {
				return true
			}
		}
	}

	return false
}

// ValidateOriginForProduction performs additional validation for production environments
func ValidateOriginForProduction(origins []string) error {
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)

		// Wildcard is not allowed in production
		if origin == "*" {
			return &OriginValidationError{
				Origin:  origin,
				Reason:  "wildcard origin is not allowed in production",
				Remediation: "specify explicit allowed origins",
			}
		}

		// Check for localhost in production
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return &OriginValidationError{
				Origin:  origin,
				Reason:  "localhost origins are not allowed in production",
				Remediation: "use production domain names",
			}
		}

		// Validate origin format
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return &OriginValidationError{
				Origin:  origin,
				Reason:  "origin must start with http:// or https://",
				Remediation: "use fully qualified origin URLs",
			}
		}
	}
	return nil
}

// OriginValidationError represents an origin validation error
type OriginValidationError struct {
	Origin      string
	Reason      string
	Remediation string
}

func (e *OriginValidationError) Error() string {
	if e.Remediation != "" {
		return "invalid origin '" + e.Origin + "': " + e.Reason + "; " + e.Remediation
	}
	return "invalid origin '" + e.Origin + "': " + e.Reason
}
