package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// OPAAuthz returns a Gin middleware that enforces OPA authorization decisions.
// It extracts JWT claims set by upstream auth middleware (user_id, roles, groups,
// tenant_id) and queries OPA for an allow/deny decision.
//
// A request proceeds only when the policy says allow AND raises no deny. That
// second half used to be missing: the middleware read decision.Allow and used
// decision.Deny as log decoration, so authz.rego's cross-tenant-access and
// separation-of-duties rules -- the two things in the policy that exist purely
// to refuse a request an allow rule would otherwise permit -- never refused
// anything. The policy's own final_allow rule says `allow; count(deny) == 0`,
// and nothing queried it: the client asks for /v1/data/openidx/authz, which
// returns the whole document. Enforcing it here rather than switching the
// query keeps a deployment shipping an older policy (one with no final_allow
// rule) safe by the same reading.
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

		// Derive the resource type from the route gin matched, never from the
		// path the caller wrote -- see inferResourceType.
		resourceType := inferResourceType(c.FullPath())

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
				logsafe.String("path", c.Request.URL.Path),
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

		// Deny overrides allow, matching the policy's own final_allow rule.
		if !decision.Allow || len(decision.Deny) > 0 {
			logger.Info("OPA denied request",
				logsafe.String("path", c.Request.URL.Path),
				logsafe.String("method", c.Request.Method),
				zap.String("user_id", uid),
				zap.Bool("allow", decision.Allow),
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

// inferResourceType maps a ROUTE TEMPLATE to the resource type OPA policies key
// on ("user", "session", "report", ...).
//
// IT TAKES THE LAST STATIC SEGMENT, NOT THE LAST SEGMENT. This read the request
// path and took whatever came last, so /api/v1/identity/users/<uuid> produced
// the UUID as the resource type -- and authz.rego keys five rules on
// input.resource.type, among them role_permissions[input.resource.type][method]
// and the "user"/"session"/"report" rules. A UUID matches none of them, so on
// EVERY endpoint that names a specific object the role-permission map silently
// did not apply and the object-scoped rules never fired. Only collection
// endpoints ever produced a type the policy could match. A rule that cannot fire
// is worse than one that denies: nothing reports it.
//
// The template's last static segment is the collection the object belongs to
// (/users/:id -> "users" -> "user"), which is the vocabulary the policy is
// written in. Callers pass c.FullPath(); an unmatched route yields "", exactly
// as a short path did before.
func inferResourceType(routeTemplate string) string {
	segments := strings.Split(strings.Trim(routeTemplate, "/"), "/")
	// Look for known resource segments: /api/v1/<service>/<resource>
	if len(segments) >= 3 {
		// e.g. /api/v1/identity/users → "user", /api/v1/identity/users/:id → "user"
		resource := ""
		for i := len(segments) - 1; i >= 0; i-- {
			if s := segments[i]; s != "" && !strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "*") {
				resource = s
				break
			}
		}
		if resource == "" {
			return ""
		}
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
