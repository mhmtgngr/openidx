package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig holds configuration for security headers middleware
type SecurityConfig struct {
	// HSTSEnabled enables Strict-Transport-Security header (recommended for production)
	HSTSEnabled bool
	// CSPEnabled enables Content-Security-Policy header
	CSPEnabled bool
	// FrameOptions sets X-Frame-Options: DENY, SAMEORIGIN, or ALLOW-FROM
	FrameOptions string
	// CSPCustom allows specifying a custom CSP policy instead of the default
	CSPCustom string
}

// DefaultSecurityConfig returns a SecurityConfig with secure defaults
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		HSTSEnabled:   true,
		CSPEnabled:    true,
		FrameOptions:  "DENY",
		CSPCustom:     "",
	}
}

// SecurityHeaders returns middleware that sets standard security response headers.
// All headers except HSTS and CSP are set by default as they're low-risk.
// HSTS and CSP can be enabled/disabled via configuration.
func SecurityHeaders(cfg SecurityConfig) gin.HandlerFunc {
	// Validate FrameOptions
	frameOpts := cfg.FrameOptions
	upper := strings.ToUpper(frameOpts)
	if upper == "DENY" || upper == "SAMEORIGIN" {
		frameOpts = upper
	} else if strings.HasPrefix(upper, "ALLOW-FROM") {
		// Preserve the URL portion after ALLOW-FROM
		frameOpts = "ALLOW-FROM" + frameOpts[len("ALLOW-FROM"):]
	} else {
		frameOpts = "DENY" // Default to most secure
	}

	return func(c *gin.Context) {
		// X-Content-Type-Options: Prevents MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// X-Frame-Options: Prevents clickjacking
		c.Header("X-Frame-Options", frameOpts)

		// X-XSS-Protection: Enables browser XSS filter (legacy but still useful)
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy: Controls referrer information sent
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions-Policy: Restricts browser features
		// Disables geolocation, microphone, and camera by default
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Strict-Transport-Security: Enforces HTTPS (only enable in production/TLS)
		if cfg.HSTSEnabled && c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content-Security-Policy: Controls resources the browser can load
		if cfg.CSPEnabled {
			csp := cfg.CSPCustom
			if csp == "" {
				// Default CSP if no custom policy provided
				csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
			}
			c.Header("Content-Security-Policy", csp)
		}

		c.Next()
	}
}

// SecurityHeadersProduction is a convenience function that returns middleware
// configured for production environments (all security headers enabled)
func SecurityHeadersProduction() gin.HandlerFunc {
	return SecurityHeaders(SecurityConfig{
		HSTSEnabled:  true,
		CSPEnabled:   true,
		FrameOptions: "DENY",
		CSPCustom:    "",
	})
}

// SecurityHeadersDevelopment returns middleware configured for development
// with HSTS disabled (since dev typically doesn't use TLS)
func SecurityHeadersDevelopment() gin.HandlerFunc {
	return SecurityHeaders(SecurityConfig{
		HSTSEnabled:  false,
		CSPEnabled:   true,
		FrameOptions: "DENY",
		CSPCustom:    "",
	})
}

// SecurityHeadersForEnv returns the appropriate security headers middleware based on environment
func SecurityHeadersForEnv(isProduction bool) gin.HandlerFunc {
	if isProduction {
		return SecurityHeadersProduction()
	}
	return SecurityHeadersDevelopment()
}

// CustomFrameOptions creates a middleware that sets a custom X-Frame-Options
// value for specific endpoints that need to be embedded (e.g., SAMEORIGIN for iframes)
func CustomFrameOptions(frameOption string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", frameOption)
		c.Next()
	}
}

// CustomCSP creates a middleware that sets a custom Content-Security-Policy
// for specific endpoints that need different policies
func CustomCSP(csp string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", csp)
		c.Next()
	}
}
