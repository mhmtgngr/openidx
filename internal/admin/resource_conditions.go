package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// APPLICATION ACCESS CONDITIONS: THE WRITE PATH.
//
// resource_conditions (migration 229) holds what an application demands of
// the situation a person reaches it in: a trusted device, a risk ceiling,
// allowed countries, a fresh second factor, a time window, a posture profile.
// internal/accessdecision reads it at every enforcement point, the OIDC
// sign-in reads require_step_up as acr urn:openidx:mfa:fresh (oauth/acr.go),
// and until this file nothing but the 229 backfill wrote it.
//
//	GET /api/v1/applications/:id/conditions
//	PUT /api/v1/applications/:id/conditions
//
// PUT replaces the whole row (legacy_roles, which only the backfill writes,
// is kept). Every write is audited with the before and after state.

// ApplicationConditions is the editable part of a resource_conditions row.
type ApplicationConditions struct {
	ApplicationID      string          `json:"application_id"`
	RequireDeviceTrust bool            `json:"require_device_trust"`
	MaxRiskScore       *int            `json:"max_risk_score"`
	AllowedCountries   []string        `json:"allowed_countries"`
	RequireStepUp      bool            `json:"require_step_up"`
	TimeWindow         json.RawMessage `json:"time_window,omitempty"`
	PostureProfileID   *string         `json:"posture_profile_id"`
	LegacyRoles        []string        `json:"legacy_roles"`
	Declared           bool            `json:"declared"`
}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

// validate normalises c and returns a message for a 400, or "".
func (c *ApplicationConditions) validate() string {
	if c.MaxRiskScore != nil && (*c.MaxRiskScore < 0 || *c.MaxRiskScore > 100) {
		return "max_risk_score must be between 0 and 100"
	}
	seen := map[string]bool{}
	countries := []string{}
	for _, cc := range c.AllowedCountries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if !countryCode.MatchString(cc) {
			return "allowed_countries must be ISO 3166-1 alpha-2 codes"
		}
		if !seen[cc] {
			seen[cc] = true
			countries = append(countries, cc)
		}
	}
	c.AllowedCountries = countries
	if c.PostureProfileID != nil {
		v := strings.TrimSpace(*c.PostureProfileID)
		if v == "" {
			c.PostureProfileID = nil
		} else if _, err := uuid.Parse(v); err != nil {
			return "posture_profile_id must be a UUID"
		} else {
			c.PostureProfileID = &v
		}
	}
	if len(c.TimeWindow) > 0 && string(c.TimeWindow) != "null" {
		var tw map[string]interface{}
		if err := json.Unmarshal(c.TimeWindow, &tw); err != nil {
			return "time_window must be a JSON object"
		}
	} else {
		c.TimeWindow = nil
	}
	return ""
}

func (s *Service) loadApplicationConditions(c *gin.Context, appID, orgID string) (*ApplicationConditions, error) {
	out := &ApplicationConditions{ApplicationID: appID, AllowedCountries: []string{}, LegacyRoles: []string{}}
	var tw []byte
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT COALESCE(rc.require_device_trust, false), rc.max_risk_score,
		       COALESCE(rc.allowed_countries, '{}'), COALESCE(rc.require_step_up, false),
		       rc.time_window, rc.posture_profile_id::text, COALESCE(rc.legacy_roles, '{}'),
		       rc.application_id IS NOT NULL
		  FROM applications a
		  LEFT JOIN resource_conditions rc ON rc.application_id = a.id
		 WHERE a.id = $1 AND a.org_id = $2`, appID, orgID).Scan(
		&out.RequireDeviceTrust, &out.MaxRiskScore, &out.AllowedCountries, &out.RequireStepUp,
		&tw, &out.PostureProfileID, &out.LegacyRoles, &out.Declared)
	if err != nil {
		return nil, err
	}
	if len(tw) > 0 {
		out.TimeWindow = json.RawMessage(tw)
	}
	return out, nil
}

func (s *Service) handleGetApplicationConditions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	appID := c.Param("id")
	if _, err := uuid.Parse(appID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	cond, err := s.loadApplicationConditions(c, appID, org.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	if err != nil {
		s.logger.Error("application conditions: read failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, cond)
}

func (s *Service) handlePutApplicationConditions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	appID := c.Param("id")
	if _, err := uuid.Parse(appID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	var req ApplicationConditions
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if msg := req.validate(); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	before, err := s.loadApplicationConditions(c, appID, org.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	if err != nil {
		s.logger.Error("application conditions: read failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	var actor *string
	if id := c.GetString("user_id"); id != "" {
		if _, perr := uuid.Parse(id); perr == nil {
			actor = &id
		}
	}
	var tw interface{}
	if req.TimeWindow != nil {
		tw = string(req.TimeWindow)
	}
	if _, err := s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO resource_conditions (application_id, org_id, require_device_trust, max_risk_score,
		       allowed_countries, require_step_up, time_window, posture_profile_id, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::uuid, NOW(), $9::uuid)
		ON CONFLICT (application_id) DO UPDATE SET
		       require_device_trust = EXCLUDED.require_device_trust,
		       max_risk_score       = EXCLUDED.max_risk_score,
		       allowed_countries    = EXCLUDED.allowed_countries,
		       require_step_up      = EXCLUDED.require_step_up,
		       time_window          = EXCLUDED.time_window,
		       posture_profile_id   = EXCLUDED.posture_profile_id,
		       updated_at           = NOW(),
		       updated_by           = EXCLUDED.updated_by
		 WHERE resource_conditions.org_id = EXCLUDED.org_id`,
		appID, org.ID, req.RequireDeviceTrust, req.MaxRiskScore, req.AllowedCountries,
		req.RequireStepUp, tw, req.PostureProfileID, actor); err != nil {
		s.logger.Error("application conditions: write failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	after, err := s.loadApplicationConditions(c, appID, org.ID)
	if err != nil {
		s.logger.Error("application conditions: re-read failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	_ = s.RecordAdminAction(c.Request.Context(),
		c.GetString("user_id"), c.GetString("email"),
		"update_application_conditions", "application", appID, "",
		c.ClientIP(), c.Request.UserAgent(), c.GetString("request_id"),
		before, after)
	c.JSON(http.StatusOK, after)
}
