package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/pamgrant"
)

// THE RULES AROUND A PRIVILEGED SESSION ARE AN ORGANIZATION'S POLICY.
//
// They used to be a constant and two column defaults: externalid.MaxPamSession
// capped external users' sessions and nobody else's, the launch-approval
// window was time.Hour in pam_launch.go, and pam_entries.require_approval and
// record_session defaulted to false, so an internal user's session was
// neither approved nor recorded unless someone set it on every entry.
//
// org_pam_policy (migration 228) holds them per organization. A missing row
// means defaultPamPolicy: every session capped at 8 h, internal sessions
// recorded, approval not required, a 60-minute window. The migration gave
// every organization that existed a row with its old behaviour, so nothing
// changed under it; a new organization starts with the defaults. External
// users keep every control in external_pam.go whatever this says, and their
// 8-hour ceiling is a floor on nothing: the policy can only shorten it.

// PamPolicy is one organization's privileged-session policy.
type PamPolicy struct {
	OrgID string `json:"org_id"`
	// MaxSessionHours caps every session; 0 is no cap for internal users.
	MaxSessionHours int `json:"max_session_hours"`
	// IdleTimeoutMinutes is stored for the day the broker reports activity;
	// nothing enforces it yet, and the console says so.
	IdleTimeoutMinutes int `json:"idle_timeout_minutes"`
	// RequireApprovalInternal asks an approver before an internal user's
	// session, on every entry, as an external user's always is.
	RequireApprovalInternal bool `json:"require_approval_internal"`
	// RecordInternal records an internal user's session on every entry.
	RecordInternal bool `json:"record_internal"`
	// LaunchApprovalWindowMinutes is how long a launch request waits for its
	// approver before it lapses.
	LaunchApprovalWindowMinutes int `json:"launch_approval_window_minutes"`
	// Source is "policy" for a stored row and "default" for the defaults.
	Source    string     `json:"source"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

func defaultPamPolicy() PamPolicy {
	return PamPolicy{
		MaxSessionHours:             pamgrant.DefaultMaxSessionHours,
		IdleTimeoutMinutes:          0,
		RequireApprovalInternal:     false,
		RecordInternal:              true,
		LaunchApprovalWindowMinutes: 60,
		Source:                      "default",
	}
}

// LaunchApprovalWindow is how long a launch request stays approvable.
func (p PamPolicy) LaunchApprovalWindow() time.Duration {
	if p.LaunchApprovalWindowMinutes <= 0 {
		return 60 * time.Minute
	}
	return time.Duration(p.LaunchApprovalWindowMinutes) * time.Minute
}

// externalSessionCap is the duration an external user's session may run:
// the policy's cap when it is shorter, never more than MaxPamSession.
func (p PamPolicy) externalSessionCap() time.Duration {
	if p.MaxSessionHours > 0 {
		if d := time.Duration(p.MaxSessionHours) * time.Hour; d < externalid.MaxPamSession {
			return d
		}
	}
	return externalid.MaxPamSession
}

// pamPolicyFor loads the organization's policy, or the defaults when it has
// none. A read that fails is logged and answered with the defaults: a launch
// must not fail because the policy table was unreachable, and the defaults
// are the stricter answer.
func (s *Service) pamPolicyFor(ctx context.Context, orgID string) PamPolicy {
	pol := defaultPamPolicy()
	pol.OrgID = orgID
	if orgID == "" || s.db == nil || s.db.Pool == nil {
		return pol
	}
	var updatedBy *string
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT max_session_hours, idle_timeout_minutes, require_approval_internal, record_internal,
		       launch_approval_window_minutes, updated_at, updated_by::text
		  FROM org_pam_policy WHERE org_id = $1::uuid`, orgID).Scan(
		&pol.MaxSessionHours, &pol.IdleTimeoutMinutes, &pol.RequireApprovalInternal, &pol.RecordInternal,
		&pol.LaunchApprovalWindowMinutes, &updatedAt, &updatedBy)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("pam policy: could not read org_pam_policy; using the defaults",
				zap.String("org_id", orgID), zap.Error(err))
		}
		return pol
	}
	pol.Source = "policy"
	pol.UpdatedAt = &updatedAt
	if updatedBy != nil {
		pol.UpdatedBy = *updatedBy
	}
	return pol
}

// pinOrgPamPolicy applies the organization's policy to an internal caller's
// launch: approval and recording are the entry's setting OR the policy's.
// An external caller is pinned by pinExternalPamPolicy and left alone here.
func pinOrgPamPolicy(entry *pamLaunchEntry, caller pamCaller, pol PamPolicy) {
	if caller.External {
		return
	}
	entry.RequireApproval = entry.RequireApproval || pol.RequireApprovalInternal
	entry.RecordSession = entry.RecordSession || pol.RecordInternal
}

// GET /pam/policy: the caller's organization's policy, defaults included.
func (s *Service) handleGetPamPolicy(c *gin.Context) {
	orgID := getOrgID(c)
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id not in auth context"})
		return
	}
	c.JSON(http.StatusOK, s.pamPolicyFor(c.Request.Context(), orgID))
}

type setPamPolicyRequest struct {
	MaxSessionHours             int  `json:"max_session_hours"`
	IdleTimeoutMinutes          int  `json:"idle_timeout_minutes"`
	RequireApprovalInternal     bool `json:"require_approval_internal"`
	RecordInternal              bool `json:"record_internal"`
	LaunchApprovalWindowMinutes int  `json:"launch_approval_window_minutes"`
}

func (r setPamPolicyRequest) validate() string {
	switch {
	case r.MaxSessionHours < 0 || r.MaxSessionHours > 168:
		return "max_session_hours must be between 0 (no cap) and 168"
	case r.IdleTimeoutMinutes < 0 || r.IdleTimeoutMinutes > 1440:
		return "idle_timeout_minutes must be between 0 and 1440"
	case r.LaunchApprovalWindowMinutes < 5 || r.LaunchApprovalWindowMinutes > 1440:
		return "launch_approval_window_minutes must be between 5 and 1440"
	}
	return ""
}

// PUT /pam/policy (admin): upsert the organization's policy.
func (s *Service) handleSetPamPolicy(c *gin.Context) {
	orgID := getOrgID(c)
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id not in auth context"})
		return
	}
	var req setPamPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := req.validate(); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	if s.db == nil || s.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	updatedBy := getUserID(c)
	_, err := s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO org_pam_policy (org_id, max_session_hours, idle_timeout_minutes, require_approval_internal,
		                            record_internal, launch_approval_window_minutes, updated_by)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, NULLIF($7,'')::uuid)
		ON CONFLICT (org_id) DO UPDATE
		   SET max_session_hours = EXCLUDED.max_session_hours,
		       idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
		       require_approval_internal = EXCLUDED.require_approval_internal,
		       record_internal = EXCLUDED.record_internal,
		       launch_approval_window_minutes = EXCLUDED.launch_approval_window_minutes,
		       updated_at = NOW(),
		       updated_by = EXCLUDED.updated_by`,
		orgID, req.MaxSessionHours, req.IdleTimeoutMinutes, req.RequireApprovalInternal,
		req.RecordInternal, req.LaunchApprovalWindowMinutes, updatedBy)
	if err != nil {
		s.logger.Error("pam policy: upsert failed", zap.String("org_id", orgID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upsert failed"})
		return
	}
	s.logAuditEvent(c, "pam.policy_set", orgID, "organization", map[string]interface{}{
		"max_session_hours":              req.MaxSessionHours,
		"idle_timeout_minutes":           req.IdleTimeoutMinutes,
		"require_approval_internal":      req.RequireApprovalInternal,
		"record_internal":                req.RecordInternal,
		"launch_approval_window_minutes": req.LaunchApprovalWindowMinutes,
	})
	c.JSON(http.StatusOK, s.pamPolicyFor(c.Request.Context(), orgID))
}
