package audit

import (
	"net/http"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// EventTypeCount is one value present in this tenant's audit trail, with how
// many rows carry it.
type EventTypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

// handleEventTypes answers which event types this tenant's audit trail actually
// contains.
//
// WHY THIS IS A QUERY AND NOT A LIST. The console's filter offered eight names
// copied from the EventType constants above -- authentication, authorization,
// user_management, group_management, role_management, configuration,
// data_access, system. Two of them are ever written. Filtering by any of the
// other six returned an empty list, and an empty audit list reads as "nothing
// happened", which on this surface is the worst available wrong answer: an
// auditor asking "show me every configuration change" was told there were none.
//
// Meanwhile the values the trail does hold could not be filtered for at all --
// identity, provisioning, oauth, access, security, and the specific events
// internal/access writes one row at a time (pam.session.risk_suspend,
// pam.recording.sealed, certificate.rotate, session.revoked.continuous_verify,
// platform_admin_cross_org_access).
//
// A catalogue would have to be kept in step with twenty writers by hand, and
// the drift it replaced is exactly what that costs. Asking the data cannot
// drift: what is offered is what is there, per tenant, always. Migration v180
// adds the (org_id, event_type) index this scan and the filter itself both
// want.
func (s *Service) handleEventTypes(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"event_types": []EventTypeCount{}})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT event_type, COUNT(*)
		FROM audit_events
		WHERE org_id = $1
		GROUP BY event_type
		ORDER BY COUNT(*) DESC, event_type ASC`, org.ID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list audit event types", err), s.logger)
		return
	}
	defer rows.Close()

	// Never nil: a tenant with no audit rows yet must render an empty filter,
	// not a JSON null the console has to guess at.
	types := []EventTypeCount{}
	for rows.Next() {
		var t EventTypeCount
		if err := rows.Scan(&t.Type, &t.Count); err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("scan audit event type", err), s.logger)
			return
		}
		types = append(types, t)
	}
	if err := rows.Err(); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("read audit event types", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"event_types": types})
}
