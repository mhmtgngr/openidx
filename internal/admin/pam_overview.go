// Package admin — PAM (Privileged Access Management) overview statistics.
//
// One aggregated endpoint for the admin console's PAM dashboard: vault
// inventory, rotation health, checkout activity, and privileged-session
// state. Registered on the admin-guarded vault group in cmd/admin-api
// (see RegisterPAMRoutes), so every caller is already an admin.
package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// PAMSecretsStats describes the vault inventory.
type PAMSecretsStats struct {
	Total  int64            `json:"total"`
	ByType map[string]int64 `json:"by_type"`
}

// PAMRotationStats describes rotation-policy health.
type PAMRotationStats struct {
	Policies        int64 `json:"policies"`
	PoliciesEnabled int64 `json:"policies_enabled"`
	PoliciesFailing int64 `json:"policies_failing"`
	PoliciesOverdue int64 `json:"policies_overdue"`
	Runs30d         int64 `json:"runs_30d"`
	Failures30d     int64 `json:"failures_30d"`
}

// PAMCheckoutStats describes credential checkout/lease activity.
type PAMCheckoutStats struct {
	ActiveLeases              int64 `json:"active_leases"`
	Checkouts30d              int64 `json:"checkouts_30d"`
	PendingCredentialRequests int64 `json:"pending_credential_requests"`
}

// PAMSessionStats describes brokered privileged-session state.
type PAMSessionStats struct {
	ActiveSessions   int64 `json:"active_sessions"`
	Sessions30d      int64 `json:"sessions_30d"`
	PendingRequests  int64 `json:"pending_requests"`
	RecordingsOnHold int64 `json:"recordings_on_hold"`
}

// PAMOverview is the aggregated response for GET /api/v1/pam/overview.
type PAMOverview struct {
	Secrets     PAMSecretsStats  `json:"secrets"`
	Rotation    PAMRotationStats `json:"rotation"`
	Checkouts   PAMCheckoutStats `json:"checkouts"`
	Sessions    PAMSessionStats  `json:"sessions"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// RegisterPAMRoutes registers the PAM overview endpoint. Mount it on an
// admin-guarded router group (cmd/admin-api mounts it on the same
// RequireAdmin group as the vault and rotation routes).
func RegisterPAMRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/pam/overview", svc.handlePAMOverview)
}

// handlePAMOverview returns aggregated PAM statistics for the caller's org.
// GET /api/v1/pam/overview (admin)
func (s *Service) handlePAMOverview(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	overview, err := s.aggregatePAMOverview(ctx, org.ID)
	if err != nil {
		s.logger.Error("handlePAMOverview: aggregation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to aggregate PAM overview"})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// aggregatePAMOverview runs the per-area stat queries. Every query carries an
// explicit org_id predicate (defence in depth on top of FORCE-RLS).
func (s *Service) aggregatePAMOverview(ctx context.Context, orgID string) (*PAMOverview, error) {
	o := &PAMOverview{
		Secrets:     PAMSecretsStats{ByType: map[string]int64{}},
		GeneratedAt: time.Now().UTC(),
	}

	// Vault inventory.
	rows, err := s.db.Pool.Query(ctx,
		`SELECT type, COUNT(*) FROM vault_secrets WHERE org_id = $1 GROUP BY type`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var typ string
		var n int64
		if err := rows.Scan(&typ, &n); err != nil {
			rows.Close()
			return nil, err
		}
		o.Secrets.ByType[typ] = n
		o.Secrets.Total += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Rotation health.
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE enabled),
		        COUNT(*) FILTER (WHERE last_status = 'failed'),
		        COUNT(*) FILTER (WHERE enabled AND next_run_at IS NOT NULL AND next_run_at < NOW())
		   FROM credential_rotation_policies
		  WHERE org_id = $1`, orgID).
		Scan(&o.Rotation.Policies, &o.Rotation.PoliciesEnabled,
			&o.Rotation.PoliciesFailing, &o.Rotation.PoliciesOverdue)
	if err != nil {
		return nil, err
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE status = 'failed')
		   FROM credential_rotations
		  WHERE org_id = $1 AND started_at > NOW() - INTERVAL '30 days'`, orgID).
		Scan(&o.Rotation.Runs30d, &o.Rotation.Failures30d)
	if err != nil {
		return nil, err
	}

	// Checkout / lease activity.
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE status = 'active'
		                           AND (expires_at IS NULL OR expires_at > NOW())),
		        COUNT(*) FILTER (WHERE leased_at > NOW() - INTERVAL '30 days')
		   FROM vault_checkouts
		  WHERE org_id = $1`, orgID).
		Scan(&o.Checkouts.ActiveLeases, &o.Checkouts.Checkouts30d)
	if err != nil {
		return nil, err
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*)
		   FROM access_requests
		  WHERE org_id = $1 AND resource_type = 'vault_credential' AND status = 'pending'`, orgID).
		Scan(&o.Checkouts.PendingCredentialRequests)
	if err != nil {
		return nil, err
	}

	// Privileged sessions.
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE status = 'active'),
		        COUNT(*) FILTER (WHERE started_at > NOW() - INTERVAL '30 days'),
		        COUNT(*) FILTER (WHERE EXISTS (
		            SELECT 1 FROM guacamole_recording_legal_holds h
		             WHERE h.session_id = guacamole_sessions.id AND h.released_at IS NULL))
		   FROM guacamole_sessions
		  WHERE org_id = $1`, orgID).
		Scan(&o.Sessions.ActiveSessions, &o.Sessions.Sessions30d, &o.Sessions.RecordingsOnHold)
	if err != nil {
		return nil, err
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*)
		   FROM guacamole_session_requests
		  WHERE org_id = $1 AND status = 'pending'
		    AND (expires_at IS NULL OR expires_at > NOW())`, orgID).
		Scan(&o.Sessions.PendingRequests)
	if err != nil {
		return nil, err
	}

	return o, nil
}
