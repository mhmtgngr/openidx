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

		// Only enforce when a session cookie is present (browser-based requests)
		_, err := c.Request.Cookie("_openidx_proxy_session")
		if err != nil {
			// No session cookie — this is a non-browser API client using Bearer auth
			c.Next()
			return
		}

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
