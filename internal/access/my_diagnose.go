package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/diagnose"
)

// fallbackLiveness is how recent a report counts as "the device is there"
// when the deployment sets no liveness timeout.
const fallbackLiveness = 10 * time.Minute

// MyDiagnosis answers "why can't I connect" for one of the caller's devices.
type MyDiagnosis struct {
	// AgentID is the device the verdict is about; empty when the caller has
	// no enrolled device at all.
	AgentID string           `json:"agent_id,omitempty"`
	Verdict diagnose.Verdict `json:"verdict"`
	// BundleAt is when the device's own doctor last reported, when that
	// report was recent enough to be used.
	BundleAt    *time.Time `json:"bundle_at,omitempty"`
	GeneratedAt time.Time  `json:"generated_at"`
}

// handleMyDiagnose diagnoses one of the caller's own devices: the newest
// reporting one, or the one named in the body.
//
// The device set comes from collectUserDevices for the authenticated user.
// A named device outside that set is "not found", the same answer as a
// device that does not exist, so the endpoint cannot be used to learn about
// anyone else's.
func (s *Service) handleMyDiagnose(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse body"})
			return
		}
	}

	devices, err := s.collectUserDevices(ctx, org.ID, uid)
	if err != nil {
		s.logger.Error("my diagnose: device lookup failed", zap.String("user_id", logsafe.Clean(uid)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up your devices"})
		return
	}
	device := pickDevice(devices, body.AgentID)
	if body.AgentID != "" && device == nil {
		s.logger.Warn("my diagnose: device is not the caller's",
			zap.String("user_id", logsafe.Clean(uid)), zap.String("agent_id", logsafe.Clean(body.AgentID)))
		c.JSON(http.StatusNotFound, gin.H{"error": "no such device"})
		return
	}

	now := time.Now().UTC()
	out := MyDiagnosis{GeneratedAt: now}
	ev := diagnose.Evidence{Now: now}
	if device != nil {
		out.AgentID = device.AgentID
		ev.Device = s.deviceFacts(device, now)
		tunnelState, bundle, err := s.deviceDiagnosticState(ctx, org.ID, device.AgentID)
		if err != nil {
			s.logger.Error("my diagnose: evidence lookup failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to gather evidence"})
			return
		}
		ev.Device.TunnelState = tunnelState
		ev.Bundle = bundle
	}
	out.Verdict = diagnose.Evaluate(ev)
	if ev.Bundle != nil && !out.Verdict.BundleStale {
		at := ev.Bundle.CollectedAt
		out.BundleAt = &at
	}
	c.JSON(http.StatusOK, out)
}

// pickDevice returns the caller's agent-backed device with this id, or, with
// no id, the one that reported most recently.
func pickDevice(devices []UserDeviceEntry, agentID string) *DeviceZiti {
	var best *DeviceZiti
	for i := range devices {
		z := devices[i].Ziti
		if z == nil || z.AgentID == "" {
			continue
		}
		if agentID != "" {
			if z.AgentID == agentID {
				return z
			}
			continue
		}
		if best == nil || reportedAfter(z, best) {
			best = z
		}
	}
	return best
}

func reportedAfter(a, b *DeviceZiti) bool {
	if a.LastReportAt == nil {
		return false
	}
	return b.LastReportAt == nil || a.LastReportAt.After(*b.LastReportAt)
}

// deviceFacts is the fleet's record of a device, in the rule engine's terms.
func (s *Service) deviceFacts(z *DeviceZiti, now time.Time) *diagnose.DeviceFacts {
	f := &diagnose.DeviceFacts{CredentialRefused: z.CredentialRefused}
	switch z.Status {
	case agentStatusRevoked, agentStatusRetired:
		f.Status = diagnose.DeviceRevoked
	case "suspended":
		f.Status = diagnose.DeviceSuspended
	case "pending":
		f.Status = diagnose.DevicePending
	default:
		f.Status = z.Status
	}
	if z.Live != nil {
		f.Live = *z.Live
	} else {
		f.Live = z.LastReportAt != nil && now.Sub(*z.LastReportAt) <= fallbackLiveness
	}
	switch z.ComplianceStatus {
	case "compliant":
		ok := true
		f.Compliant = &ok
	case "non_compliant":
		ok := false
		f.Compliant = &ok
	}
	return f
}

// deviceDiagnosticState reads what only the fleet tables hold about a
// device: the tunnel state it last reported and its newest diagnostic bundle.
func (s *Service) deviceDiagnosticState(ctx context.Context, orgID, agentID string) (string, *diagnose.Bundle, error) {
	var tunnelState string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(tunnel_status->>'state', '') FROM enrolled_agents
		 WHERE org_id = $1 AND agent_id = $2`, orgID, agentID).Scan(&tunnelState)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, err
	}
	var doc []byte
	err = s.db.Pool.QueryRow(ctx, `
		SELECT bundle FROM agent_diagnostics
		 WHERE org_id = $1 AND agent_id = $2 AND expires_at > NOW()
		 ORDER BY created_at DESC, id DESC LIMIT 1`, orgID, agentID).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return tunnelState, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	bundle, err := diagnose.ParseBundle(doc)
	if err != nil {
		// A stored bundle this build no longer reads is not evidence, and not
		// a reason to refuse the question.
		s.logger.Warn("my diagnose: stored bundle does not parse", zap.Error(err))
		return tunnelState, nil, nil
	}
	return tunnelState, bundle, nil
}

// handleDecodeSupportCode turns the support code a user read out into the
// verdict it stands for. The code names failed checks and nothing else, so
// there is no device to look up and nothing tenant-specific in the answer.
func (s *Service) handleDecodeSupportCode(c *gin.Context) {
	var body struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}
	codes, err := diagnose.DecodeSupportCode(body.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "that is not a valid support code; ask for it to be read again"})
		return
	}
	// The device exists (someone is holding it) and its record is unknown:
	// only what the code says is judged.
	verdict := diagnose.Evaluate(diagnose.Evidence{
		Bundle: diagnose.BundleFromCodes(codes),
		Device: &diagnose.DeviceFacts{Status: diagnose.DeviceActive, Live: true},
	})
	c.JSON(http.StatusOK, gin.H{"doctor_codes": codes, "verdict": verdict})
}
