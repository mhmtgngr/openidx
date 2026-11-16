package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/diagnose"
)

// diagnosticsKeptPerAgent is how many bundles one device keeps. A device that
// cannot connect may send one on every retry; the recent few are evidence,
// the rest is noise.
const diagnosticsKeptPerAgent = 20

// HandleAgentDiagnostics stores what a device's own doctor found.
//
// The bundle comes from a machine the server does not control. It is read up
// to a fixed size, parsed strictly and bounded (diagnose.ParseBundle), and
// re-encoded from the parsed form before it is stored, so nothing the parser
// did not recognise reaches the table. The agent_id inside the bundle is
// ignored: the row belongs to the device whose credential made the request.
func (h *AgentAPIHandler) HandleAgentDiagnostics(c *gin.Context) {
	agentID, ok := h.requireEnrolledAgent(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, diagnose.MaxBundleBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	if len(raw) > diagnose.MaxBundleBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "the bundle exceeds 64 KiB"})
		return
	}
	if !h.requireDeviceSignature(c, agentID, raw) {
		return
	}
	bundle, err := diagnose.ParseBundle(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not a diagnostic bundle this server understands"})
		return
	}
	bundle.AgentID = agentID

	ctx := c.Request.Context()
	now := time.Now().UTC()
	// A device's clock is one of the things being diagnosed: a collection
	// time from the future, or from long ago, is replaced by ours.
	if bundle.CollectedAt.After(now.Add(time.Minute)) || now.Sub(bundle.CollectedAt) > 24*time.Hour {
		bundle.CollectedAt = now
	}
	verdict := diagnose.Evaluate(diagnose.Evidence{
		Now:    now,
		Bundle: bundle,
		// The credential was just accepted, so the device exists, is not
		// revoked and is plainly reachable. Everything else the server
		// knows is merged in when someone asks about this device.
		Device: &diagnose.DeviceFacts{Status: diagnose.DeviceActive, Live: true},
	})

	id, err := h.storeAgentDiagnostic(ctx, agentID, "agent", bundle, verdict.Primary())
	if err != nil {
		h.logger.Error("store agent diagnostic failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store the bundle"})
		return
	}
	outcome := "healthy"
	if !verdict.Healthy {
		outcome = verdict.Primary()
	}
	h.logAuditEvent("agent.diagnostic.uploaded", agentID, outcome, "diagnostic="+id)
	h.logAuditEventToDB(ctx, "agent.diagnostic.uploaded", agentID, outcome, "diagnostic="+id)
	c.JSON(http.StatusOK, gin.H{"id": id, "verdict": verdict})
}

// storeAgentDiagnostic writes one bundle for a device of the tenant on ctx
// and drops that device's bundles beyond the most recent few.
func (h *AgentAPIHandler) storeAgentDiagnostic(ctx context.Context, agentID, source string, b *diagnose.Bundle, primary string) (string, error) {
	orgID := orgIDFrom(ctx)
	if orgID == "" {
		return "", errors.New("no organization on the request")
	}
	doc, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	var cause interface{}
	if primary != "" {
		cause = primary
	}
	var id string
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO agent_diagnostics (org_id, agent_id, source, bundle, primary_cause, collected_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6)
		RETURNING id::text`,
		orgID, agentID, source, string(doc), cause, b.CollectedAt).Scan(&id); err != nil {
		return "", err
	}
	if _, err := h.db.Pool.Exec(ctx, `
		DELETE FROM agent_diagnostics
		 WHERE org_id = $1 AND agent_id = $2
		   AND id NOT IN (SELECT id FROM agent_diagnostics
		                   WHERE org_id = $1 AND agent_id = $2
		                   ORDER BY created_at DESC, id DESC LIMIT $3)`,
		orgID, agentID, diagnosticsKeptPerAgent); err != nil {
		h.logger.Debug("trim agent diagnostics failed", zap.Error(err))
	}
	return id, nil
}

// fileDiagnoseResult stores the bundle a device returned for a "diagnose"
// command. The command is already answered; a result that holds no readable
// bundle is logged and dropped, never an error to the device.
func (h *AgentAPIHandler) fileDiagnoseResult(ctx context.Context, agentID string, result json.RawMessage) {
	var body struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(result, &body); err != nil || len(body.Bundle) == 0 {
		h.logger.Warn("diagnose result carries no bundle", zap.String("agent_id", agentID))
		return
	}
	bundle, err := diagnose.ParseBundle(body.Bundle)
	if err != nil {
		h.logger.Warn("diagnose result bundle refused", zap.String("agent_id", agentID), zap.Error(err))
		return
	}
	bundle.AgentID = agentID
	now := time.Now().UTC()
	if bundle.CollectedAt.After(now.Add(time.Minute)) || now.Sub(bundle.CollectedAt) > 24*time.Hour {
		bundle.CollectedAt = now
	}
	verdict := diagnose.Evaluate(diagnose.Evidence{
		Now: now, Bundle: bundle,
		Device: &diagnose.DeviceFacts{Status: diagnose.DeviceActive, Live: true},
	})
	id, err := h.storeAgentDiagnostic(ctx, agentID, "command", bundle, verdict.Primary())
	if err != nil {
		h.logger.Error("store diagnose result failed", zap.Error(err))
		return
	}
	outcome := "healthy"
	if !verdict.Healthy {
		outcome = verdict.Primary()
	}
	h.logAuditEvent("agent.diagnostic.uploaded", agentID, outcome, "diagnostic="+id+" source=command")
	h.logAuditEventToDB(ctx, "agent.diagnostic.uploaded", agentID, outcome, "diagnostic="+id+" source=command")
}

// expireAgentDiagnostics removes bundles past their retention.
func (h *AgentAPIHandler) expireAgentDiagnostics(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	if _, err := h.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide sweep: retention is a property of each row's own expires_at
		`DELETE FROM agent_diagnostics WHERE expires_at <= NOW()`); err != nil {
		h.logger.Debug("expire agent diagnostics failed", zap.Error(err))
	}
}
