package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CSRFConfig configures the CSRF protection middleware
type CSRFConfig struct {
	// Enabled controls whether CSRF protection is active
	Enabled bool
	// TrustedDomain is the domain from which requests are allowed (e.g., "example.com")
	TrustedDomain string
	// SessionCookieNames is a list of cookie names that indicate a session-based request
	// If any of these cookies are present, CSRF protection is enforced
	SessionCookieNames []string
}

// CSRFProtection validates the Origin/Referer headers on state-changing requests
// that include cookie-based session credentials. This prevents cross-site request
// forgery attacks on the access proxy's cookie-authenticated endpoints.
//
// Requests with only Bearer token authentication (no cookies) are not affected,
// as Bearer tokens are inherently CSRF-safe.
func CSRFProtection(cfg CSRFConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		// Only check state-changing methods
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		// Determine which cookie names to check for session-based auth
		sessionCookieNames := cfg.SessionCookieNames
		if len(sessionCookieNames) == 0 {
			// Default to the standard proxy session cookie
			sessionCookieNames = []string{"_openidx_proxy_session"}
		}

		// Only enforce when a session cookie is present (browser-based requests)
		hasSessionCookie := false
		for _, cookieName := range sessionCookieNames {
			if _, err := c.Request.Cookie(cookieName); err == nil {
				hasSessionCookie = true
				break
			}
		}

		// Skip CSRF if:
		// 1. No session cookie present (API client using Bearer auth only)
		// 2. Bearer token is present (but also check for session cookie)
		if !hasSessionCookie {
			// No session cookie — this is a non-browser API client using Bearer auth
			c.Next()
			return
		}

		// If both session cookie AND Bearer token are present, we still need CSRF protection
		// because the session cookie could be used for CSRF attacks

		// Validate Origin header first (preferred)
		origin := c.GetHeader("Origin")
		if origin != "" {
			if isAllowedOrigin(origin, cfg.TrustedDomain) {
				c.Next()
				return
			}
			logger.Warn("CSRF: Origin header rejected",
				zap.String("origin", origin),
				zap.String("trusted_domain", cfg.TrustedDomain))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "cross-origin request blocked",
			})
			return
		}

		// Fall back to Referer header
		referer := c.GetHeader("Referer")
		if referer != "" {
			if isAllowedReferer(referer, cfg.TrustedDomain) {
				c.Next()
				return
			}
			logger.Warn("CSRF: Referer header rejected",
				zap.String("referer", referer),
				zap.String("trusted_domain", cfg.TrustedDomain))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "cross-origin request blocked",
			})
			return
		}

		// Cookie present but no Origin/Referer — block (suspicious browser request)
		logger.Warn("CSRF: Cookie-authenticated request with no Origin/Referer header",
			zap.String("path", c.Request.URL.Path),
			zap.String("method", method))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "missing origin header",
		})
	}
}

// isAllowedOrigin checks if the Origin header matches the trusted domain
func isAllowedOrigin(origin, trustedDomain string) bool {
	if trustedDomain == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return matchesDomain(parsed.Hostname(), trustedDomain)
}

// isAllowedReferer checks if the Referer header matches the trusted domain
func isAllowedReferer(referer, trustedDomain string) bool {
	if trustedDomain == "" {
		return true
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return false
	}
	return matchesDomain(parsed.Hostname(), trustedDomain)
}

// matchesDomain checks if host matches domain or is a subdomain of it
func matchesDomain(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// CookieConfig provides secure cookie configuration for session management
type CookieConfig struct {
	Name     string
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// DefaultCSRFCookieConfig returns a secure cookie configuration for CSRF tokens
// configured for MFA service sessions with SameSite=Strict
func DefaultCSRFCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     "_openidx_mfa_csrf",
		Path:     "/",
		MaxAge:   3600, // 1 hour
		Secure:   true, // Use HTTPS in production
		HttpOnly: false, // CSRF token needs to be accessible by JavaScript
		SameSite: http.SameSiteStrictMode,
	}
}

// SameSiteFromString converts a string to http.SameSite
// Supported values: "default", "none", "lax", "strict"
func SameSiteFromString(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteDefaultMode
	}
}

// MFACSRFConfig returns CSRF configuration specifically for the MFA service
// It includes the MFA session cookie in the list of cookies to check
func MFACSRFConfig(trustedDomain string) CSRFConfig {
	return CSRFConfig{
		Enabled: true,
		TrustedDomain: trustedDomain,
		SessionCookieNames: []string{
			"_openidx_mfa_session",
			"_openidx_proxy_session",
		},
	}
}
