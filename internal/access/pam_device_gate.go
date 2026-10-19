package access

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/common/logsafe"
)

// PAM_DEVICE_GATE: A PRIVILEGED SESSION STARTS FROM A PERSON WITH A LIVE DEVICE.
//
// A privileged session is launched from the console in a browser, and nothing
// on that path asked whether the person had a device checking in: the agent
// could have been stopped, or never installed, and the session to a
// production server opened all the same. Under this gate an internal user's
// launch requires an enrolled device that is active, compliant and reporting
// within AGENT_LIVENESS_TIMEOUT (accessdecision.UserHasLiveDevice).
//
// External users (vendors) are not held to it: they work with nothing
// installed by design, and their sessions are bounded by engagements, the
// overlay requirement and recording instead.
//
//	off     — nothing is checked (the default).
//	observe — a launch that would be refused is audited as
//	          pam.device.would_deny and goes ahead.
//	enforce — it is refused with 403 before any credential is resolved.

// refuseNoLiveDevice writes the refusal and returns true when the launch must
// not proceed.
func (s *Service) refuseNoLiveDevice(c *gin.Context, orgID string, caller pamCaller, entryID string) bool {
	if s.config == nil || caller.External || caller.UserID == "" {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(s.config.PAMDeviceGate))
	if mode != "observe" && mode != "enforce" {
		return false
	}
	enforce := mode == "enforce"
	live, err := accessdecision.UserHasLiveDevice(c.Request.Context(), s.db, orgID, caller.UserID, s.config.AgentLiveness())
	if err != nil {
		s.logger.Error("pam device gate: device lookup failed", zap.Error(err))
		if enforce {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "device trust could not be verified"})
			return true
		}
		return false
	}
	if live {
		return false
	}
	action := "pam.device.would_deny"
	if enforce {
		action = "pam.device.denied"
	}
	details := map[string]interface{}{
		"user_id":  caller.UserID,
		"entry_id": entryID,
		"code":     accessdecision.ReasonDeviceTrust,
		"enforced": enforce,
	}
	s.logAuditEvent(c, action, entryID, "pam_entry", details)
	// The unified row is what the console's would-deny count reads.
	if s.auditService != nil {
		if err := s.auditService.RecordEvent(c.Request.Context(), "access-service", action, "", caller.UserID, c.ClientIP(), details); err != nil {
			s.logger.Warn("pam device gate: decision not recorded", zap.String("action", action), zap.Error(err))
		}
	}
	s.logger.Warn("PAM launch without a live device",
		zap.String("entry_id", logsafe.Clean(entryID)), zap.Bool("enforced", enforce))
	if !enforce {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error": "a privileged session needs a trusted device: launch it from a computer where the OpenIDX agent is running and compliant",
		"code":  accessdecision.ReasonDeviceTrust,
	})
	return true
}
