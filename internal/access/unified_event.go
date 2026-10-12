package access

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// recordUnifiedEvent writes an access-service event to the unified audit trail
// under the given tenant, or the request's when none is given. It was written
// for the temporary access links (retired in D2, tables dropped in migration
// 236), whose events were a zap log line until then; the Guacamole legal-hold
// events had the same log-only helper and ride it too.
//
// The actor is the acting administrator when there is one and nobody when
// there is not.
//
// An audit write must never fail the thing it records, so a failure is logged
// at error level with the event it lost rather than returned. An access
// service built without a unified audit store (tests) logs the event instead
// and says so.
func (s *Service) recordUnifiedEvent(c *gin.Context, orgID, eventType, actorUserID, targetID, targetType string, details map[string]interface{}) {
	if orgID == "" {
		if org, err := orgctx.From(c.Request.Context()); err == nil {
			orgID = org.ID
		}
	}
	clientIP := c.ClientIP()
	// The details carry what the request said about itself (its address, its
	// user agent, a reason typed by the caller), so what reaches the log is
	// scrubbed the way every other param-derived field in this package is.
	detailsJSON := ""
	if b, err := json.Marshal(details); err == nil {
		detailsJSON = string(b)
	}
	if s.auditService == nil {
		s.logger.Warn("unified audit: no unified audit store, event not recorded",
			zap.String("event_type", eventType), logsafe.String("target_id", targetID),
			logsafe.String("details", detailsJSON), logsafe.String("ip", clientIP))
		return
	}
	ctx := orgctx.WithBypassRLS(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
	if err := s.auditService.RecordEvent(ctx, "openidx", eventType, "", actorUserID, clientIP, details); err != nil {
		s.logger.Error("unified audit: write failed",
			zap.String("event_type", eventType), logsafe.String("target_id", targetID),
			logsafe.String("details", detailsJSON), logsafe.String("ip", clientIP), zap.Error(err))
	}
	// An event with an authenticated actor has an organization on the request,
	// so it also goes to the audit service's own stream, as every other
	// administrative action in this package does. An actorless event does not:
	// that stream resolves the tenant from the request.
	if actorUserID != "" {
		s.logAuditEvent(c, eventType, targetID, targetType, details)
	}
}
