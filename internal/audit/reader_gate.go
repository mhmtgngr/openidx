package audit

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/auth"
)

// The audit trail is read by the roles internal/auth gives audit:read:
// super_admin, admin, operator, auditor and compliance_reader. Every one of
// them also holds audit:export there, so one gate covers the reads, the
// reports and the exports alike. The routes asked only for a signed-in user,
// so any account in the organization -- a plain user, an external one --
// could read, search, stream and export the whole trail and schedule reports
// over it.

// holdsAuditRead reports whether any of roles carries audit:read. A role the
// product does not define carries nothing, and so does a machine credential
// that holds no role.
func holdsAuditRead(roles []string) bool {
	for _, r := range roles {
		if auth.HasPermission(auth.Role(r), "audit", "read") {
			return true
		}
	}
	return false
}

// refuseAuditReader answers a caller who may not read the trail.
func refuseAuditReader(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error": "reading the audit trail needs the auditor, compliance_reader, operator or administrator role",
		"code":  "audit_reader_required",
	})
}

// requireAuditReader runs after the authentication middleware on every audit
// read, report, export and stream route. It is a pass-through only where that
// middleware is not mounted either: outside production with no OAUTH_JWKS_URL,
// where cmd/audit-service serves these routes unauthenticated and says so at
// start-up (in production it refuses to start).
func (s *Service) requireAuditReader() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.config != nil && s.config.OAuthJWKSURL == "" && !s.config.IsProduction() {
			c.Next()
			return
		}
		if holdsAuditRead(c.GetStringSlice("roles")) {
			c.Next()
			return
		}
		refuseAuditReader(c)
	}
}
