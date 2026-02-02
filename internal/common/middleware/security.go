package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders returns middleware that sets standard security response headers.
// When production is true, HSTS and CSP headers are also included.
func SecurityHeaders(production bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if production {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		}

		c.Next()
	}
}
