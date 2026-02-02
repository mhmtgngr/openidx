package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// OPAAuthz returns a Gin middleware that enforces OPA authorization decisions.
// It extracts JWT claims set by upstream auth middleware (user_id, roles, groups,
// tenant_id) and queries OPA for an allow/deny decision.
//
// If OPA is unreachable and devMode is true, requests are allowed through.
// In production (devMode=false), unreachable OPA results in 403.
func OPAAuthz(client *opa.Client, logger *zap.Logger, devMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		uid, _ := userID.(string)

		rolesRaw, _ := c.Get("roles")
		roles, _ := rolesRaw.([]string)
		if roles == nil {
			roles = []string{}
		}

		groupsRaw, _ := c.Get("groups")
		groups, _ := groupsRaw.([]string)

		tenantID, _ := c.Get("tenant_id")
		tid, _ := tenantID.(string)

		// Derive resource type from the request path
		resourceType := inferResourceType(c.Request.URL.Path)

		input := opa.Input{
			User: opa.UserContext{
				ID:            uid,
				Roles:         roles,
				Groups:        groups,
				TenantID:      tid,
				Authenticated: uid != "",
			},
			Resource: opa.ResourceContext{
				Type: resourceType,
			},
			Method: c.Request.Method,
			Path:   c.Request.URL.Path,
		}

		decision, err := client.Authorize(c.Request.Context(), input)
		if err != nil {
			logger.Warn("OPA authorization error",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
				zap.String("user_id", uid),
			)
			if devMode {
				// In development, allow through if OPA is unreachable
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "authorization service unavailable",
			})
			return
		}

		if !decision.Allow {
			logger.Info("OPA denied request",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
				zap.String("user_id", uid),
				zap.Strings("deny_reasons", decision.Deny),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "access denied by policy",
				"reasons": decision.Deny,
			})
			return
		}

		c.Next()
	}
}

// inferResourceType maps URL path segments to resource types used in OPA policies
func inferResourceType(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	// Look for known resource segments: /api/v1/<service>/<resource>
	if len(segments) >= 3 {
		// e.g. /api/v1/identity/users → "user"
		resource := segments[len(segments)-1]
		// Strip trailing 's' for plurals to match OPA resource types
		if strings.HasSuffix(resource, "ies") {
			resource = strings.TrimSuffix(resource, "ies") + "y"
		} else if strings.HasSuffix(resource, "ses") {
			resource = strings.TrimSuffix(resource, "ses") + "s"
		} else if strings.HasSuffix(resource, "s") {
			resource = strings.TrimSuffix(resource, "s")
		}
		return resource
	}
	return ""
}
