package access

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ONE DECISION FOR BOTH PROXY PATHS.
//
// handleProxy (the built-in reverse proxy) and handleAuthDecide (the APISIX
// forward-auth hook, which is the path a production edge uses) grew apart:
// the first overlaid application assignment on the route's roles and groups,
// the second never checked assignment at all. A route the console showed as
// assigned to three people was open to every signed-in user behind the edge.
//
// reachDecision is the one call both make. It asks internal/accessdecision
// whether the session's user may reach the route's application, caches the
// answer per (user, application) for decisionTTL so forward-auth's per-request
// fan-out does not become a per-request query, records the decision on both
// branches the way the assignment gate always did, and answers the request
// when the verdict is a refusal. The route's own roles and groups keep
// ruling in observe mode, exactly as before; under enforcement the
// application's principals and conditions are the verdict.

// reachDecision evaluates, records and, on a refusal, answers. ok is false
// when the caller must return.
func (s *Service) reachDecision(c *gin.Context, route *ProxyRoute, session *ProxySession, appID, appOrgID, point string) (ok bool) {
	if appID == "" {
		return true // no application behind the route: nothing to decide here
	}
	ctx := c.Request.Context()
	key := session.UserID + "|" + appID
	fresh := true
	var d accessdecision.Decision
	var cached assignCacheEntry
	if v, hit := s.assignCache.Load(key); hit {
		if e, ok := v.(assignCacheEntry); ok {
			cached = e
			if e.hasDecision && time.Since(e.at) < groupCacheTTL {
				d, fresh = e.decision, false
			}
		}
	}
	if fresh {
		var err error
		// The assignment tables are the tenant's; the lookup runs bypassed
		// because the proxy session's context may not carry the org yet.
		d, err = accessdecision.Evaluate(orgctx.WithBypassRLS(ctx), s.db, s.config.AccessAssignmentEnforce,
			accessdecision.Subject{UserID: session.UserID, OrgID: appOrgID, Roles: session.Roles}, appID)
		if err != nil {
			s.logger.Error("reach decision failed", zap.String("application_id", appID), zap.Error(err))
			if s.config.AccessAssignmentEnforce {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access could not be verified"})
				return false
			}
			return true
		}
		cached.decision, cached.hasDecision = d, true
		cached.assigned, cached.at = d.Grant != "", time.Now()
		s.assignCache.Store(key, cached)
	}

	if d.WouldDeny {
		// The durable record, on both branches: enforcement is never quieter
		// than observe mode. Throttled to one per cache TTL per (user, app)
		// in observe mode, where every asset load would otherwise write.
		if !d.Allowed || fresh {
			s.recordAssignmentDecision(ctx, route, session.UserID, appID, c.ClientIP(), !d.Allowed)
		}
		details := map[string]interface{}{
			"enforcement_point": point,
			"user_id":           session.UserID,
			"route":             route.Name,
			"application_id":    appID,
			"explain":           accessdecision.Explain(d),
			"reasons":           d.Reasons,
		}
		if !d.Allowed {
			details["reason"] = "not_assigned"
			details["path"] = c.Request.URL.Path
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", details)
			c.JSON(http.StatusForbidden, gin.H{"error": "not assigned to this application"})
			return false
		} else if fresh {
			s.logAuditEvent(c, "access.assignment.would_deny", appID, "application", details)
		}
	}
	return true
}

// explainReach answers GET /decisions/explain?user=&app= for an
// administrator: the decision the enforcement points would take for that
// person on that application, with the grant and every condition named. The
// situation (device, risk, country) is not known here, so those conditions
// are listed as unjudged; the audit log carries the judged ones.
func (s *Service) handleExplainReach(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org context required"})
		return
	}
	userID, appID := c.Query("user"), c.Query("app")
	if userID == "" || appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user and app are required"})
		return
	}
	roles, err := s.userRoleNames(c.Request.Context(), userID, org.ID)
	if err != nil {
		s.logger.Warn("explain: roles", zap.Error(err))
	}
	d, err := accessdecision.Evaluate(c.Request.Context(), s.db, s.config.AccessAssignmentEnforce,
		accessdecision.Subject{UserID: userID, OrgID: org.ID, Roles: roles}, appID)
	if err != nil {
		s.logger.Error("explain: evaluate", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "evaluation failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decision": d, "explain": accessdecision.Explain(d)})
}

// userRoleNames is the user's role names in the organization, for legacy
// roles kept on a resource's conditions.
func (s *Service) userRoleNames(ctx context.Context, userID, orgID string) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id = $1 AND ur.org_id = $2
		   AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return out, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
