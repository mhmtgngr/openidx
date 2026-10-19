package oauth

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/appaccess"
)

// SSO_DEVICE_GATE: AN APPLICATION THAT REQUIRES A TRUSTED DEVICE ASKS FOR ONE AT SIGN-IN.
//
// assignmentGateAllows evaluates the application without knowing the
// situation, so a resource condition "require_device_trust" was listed
// unjudged and never refused a sign-in: an application an administrator
// marked as device-only was one browser sign-in away from anyone assigned to
// it, with no agent anywhere. ssoDeviceGateAllows judges it the one way this
// path can: the person must have a device that is active, compliant and
// reporting now (accessdecision.UserHasLiveDevice).
//
//	off     — nothing is checked (the default).
//	observe — a sign-in that would be refused is recorded as
//	          access.device.would_deny and goes ahead.
//	enforce — it is refused with 403.
func (s *Service) ssoDeviceGateAllows(c *gin.Context, userID, clientID, appID, orgID string) bool {
	if s.config == nil || appID == "" || userID == "" {
		return true
	}
	mode := strings.ToLower(strings.TrimSpace(s.config.SSODeviceGate))
	if mode != "observe" && mode != "enforce" {
		return true
	}
	enforce := mode == "enforce"
	ctx := c.Request.Context()

	res, err := accessdecision.LoadResource(ctx, s.db, appID, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true
		}
		s.logger.Error("sso device gate: application lookup failed", zap.String("application_id", appID), zap.Error(err))
		return s.ssoDeviceGateUnavailable(c, enforce)
	}
	if !res.Conditions.RequireDeviceTrust {
		return true
	}
	live, err := accessdecision.UserHasLiveDevice(ctx, s.db, orgID, userID, s.config.AgentLiveness())
	if err != nil {
		s.logger.Error("sso device gate: device lookup failed", zap.String("application_id", appID), zap.Error(err))
		return s.ssoDeviceGateUnavailable(c, enforce)
	}
	if live {
		return true
	}
	meta := map[string]interface{}{
		"reason":            accessdecision.ReasonDeviceTrust,
		"enforcement_point": "oidc",
		"client_id":         clientID,
		"detail":            "no active, compliant device reporting within the liveness timeout",
	}
	// The unified row is what the console's would-deny count reads (on both
	// branches, so enforcing is never quieter than observing); audit_events
	// carries the sign-in refusal for the audit API.
	eventType := "access.device.would_deny"
	if enforce {
		eventType = "access.device.denied"
	}
	meta["application_id"] = appID
	if err := s.recordUnifiedEvent(ctx, appaccess.SourceOIDC, eventType, "", userID, c.ClientIP(), meta); err != nil {
		s.logger.Warn("sso device gate: decision not recorded", zap.String("event_type", eventType), zap.Error(err))
	}
	if !enforce {
		return true
	}
	s.logAuditEvent(ctx, "authentication", "oauth", "oauth_access_denied", "denied",
		userID, c.ClientIP(), appID, "application", meta)
	c.JSON(403, gin.H{
		"error":             "access_denied",
		"error_description": "This application requires a trusted device: sign in from a computer where the OpenIDX agent is running and compliant.",
	})
	return false
}

// ssoDeviceGateUnavailable answers a lookup failure: refused under enforce, as
// the assignment gate does, and let through while the gate only observes.
func (s *Service) ssoDeviceGateUnavailable(c *gin.Context, enforce bool) bool {
	if !enforce {
		return true
	}
	c.JSON(503, gin.H{
		"error":             "temporarily_unavailable",
		"error_description": "device trust could not be verified",
	})
	return false
}
