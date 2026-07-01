package audit

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// CrossOrgAuditor returns the TenantResolverConfig.OnPlatformCrossOrg hook
// for a service: it records a mandatory audit_events row whenever a platform
// admin (super_admin) crosses an org boundary via the X-Org-ID header. The
// event is written under the TARGET org's id so it shows up in that tenant's
// audit trail, with the acting platform admin captured as the actor.
//
// It is intentionally best-effort and synchronous (the resolver calls it
// inline): a failed insert is logged rather than blocking the request, but the
// access still proceeds only after the attempt.
func CrossOrgAuditor(pool *pgxpool.Pool, logger *zap.Logger) func(c *gin.Context, target orgctx.Org) {
	return func(c *gin.Context, target orgctx.Org) {
		if pool == nil {
			return
		}
		actorID := c.GetString("user_id")
		var actorIDArg interface{}
		if actorID != "" {
			actorIDArg = actorID
		}
		details, _ := json.Marshal(map[string]interface{}{
			"target_org_id":   target.ID,
			"target_org_slug": target.Slug,
			"method":          c.Request.Method,
			"path":            c.Request.URL.Path,
		})
		// Bypass RLS: this is a legitimately cross-org write — it records the
		// TARGET org's audit row from a session scoped to a different org, so the
		// fail-closed WITH CHECK (org_id == app.org_id) would otherwise reject it
		// under the non-owner openidx_app role, silently dropping the mandatory
		// cross-org audit trail.
		if _, err := pool.Exec(orgctx.WithBypassRLS(c.Request.Context()),
			`INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
			                           actor_id, actor_type, actor_ip, target_id, target_type,
			                           details, org_id)
			 VALUES ($1, NOW(), 'platform_admin_cross_org_access', 'security', 'cross_org_access', 'success',
			         $2, 'platform_admin', $3, $4, 'organization', $5, $6)`,
			uuid.New().String(), actorIDArg, c.ClientIP(), target.ID, details, target.ID); err != nil {
			// Best-effort, but never silent: a failed mandatory cross-org audit
			// must be visible (it does not block the request).
			if logger != nil {
				logger.Error("failed to record platform-admin cross-org access audit",
					zap.String("target_org_id", target.ID),
					zap.String("actor_id", actorID),
					zap.Error(err))
			}
		}
	}
}
