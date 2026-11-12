package access

// Remote fleet commands (Faz B8.6, v254).
//
// An administrator queues a command for one device; the device receives it
// in its next /agent/config (once: the row moves to delivered as it is
// handed over) and answers POST /agent/commands/:id/result. The kinds:
//
//	restart        the service exits and the service manager restarts it.
//	collect_logs   the agent's and tunneler's logs and a redacted agent.json,
//	               as a tar.gz artifact of at most 8 MiB.
//	reenroll       enrol again with the sealed fleet token.
//	set_options    {log_level, tray_hidden, tunnel_enabled}.
//	update_now     run the update check now, under the update ring.
//	uninstall      acknowledge, then remove the product (msiexec /x).
//
// Queueing is operator tier; reenroll and uninstall also need a fresh second
// factor, and uninstall a written reason. A command nobody picked up within
// 24 hours expires (the leader's enforcer loop); one still queued can be
// cancelled.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

const (
	maxCommandArtifactBytes = 8 << 20
	// maxCommandResultBody bounds a result body: the artifact base64-encoded
	// plus room for the rest.
	maxCommandResultBody = maxCommandArtifactBytes*4/3 + 64<<10
	// maxQueuedCommandsPerAgent keeps a stuck device's queue bounded.
	maxQueuedCommandsPerAgent = 20
)

// agentCommandKinds are the kinds a command may have; the value says whether
// queueing it needs a fresh second factor.
var agentCommandKinds = map[string]bool{
	"restart":      false,
	"collect_logs": false,
	"reenroll":     true,
	"set_options":  false,
	"update_now":   false,
	"uninstall":    true,
}

// agentCommandDelivery is one command as /agent/config hands it to a device.
type agentCommandDelivery struct {
	ID   string          `json:"id"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args,omitempty"`
}

// agentCommandRecord is one command as the console lists it.
type agentCommandRecord struct {
	ID             string          `json:"id"`
	AgentID        string          `json:"agent_id"`
	Kind           string          `json:"kind"`
	Args           json.RawMessage `json:"args,omitempty"`
	Status         string          `json:"status"`
	Reason         string          `json:"reason,omitempty"`
	CreatedBy      string          `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	DeliveredAt    *time.Time      `json:"delivered_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Result         json.RawMessage `json:"result,omitempty"`
	ArtifactName   string          `json:"artifact_name,omitempty"`
	ArtifactSHA256 string          `json:"artifact_sha256,omitempty"`
	ArtifactSize   int             `json:"artifact_size,omitempty"`
}

// commandOptions is set_options' argument object.
type commandOptions struct {
	LogLevel      *string `json:"log_level,omitempty"`
	TrayHidden    *bool   `json:"tray_hidden,omitempty"`
	TunnelEnabled *bool   `json:"tunnel_enabled,omitempty"`
}

// validCommandArgs checks and normalizes a command's arguments.
func validCommandArgs(kind string, raw json.RawMessage) (json.RawMessage, string) {
	if kind != "set_options" {
		return json.RawMessage(`{}`), ""
	}
	var o commandOptions
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) == 0 || dec.Decode(&o) != nil {
		return nil, "set_options takes {log_level, tray_hidden, tunnel_enabled}"
	}
	if o.LogLevel == nil && o.TrayHidden == nil && o.TunnelEnabled == nil {
		return nil, "set_options needs at least one option"
	}
	if o.LogLevel != nil {
		switch *o.LogLevel {
		case "debug", "info", "warn", "error":
		default:
			return nil, "log_level must be debug, info, warn or error"
		}
	}
	out, _ := json.Marshal(o)
	return out, ""
}

// gateCommandKind applies gate to a POST /agents/:id/commands whose kind
// needs a fresh second factor, so a restart is never interrupted and an
// uninstall always is. The body is read and put back for the handler.
func gateCommandKind(gate gin.HandlerFunc) gin.HandlerFunc {
	if gate == nil {
		return nil
	}
	return func(c *gin.Context) {
		raw, _ := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
		var b struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(raw, &b)
		if agentCommandKinds[b.Kind] {
			gate(c)
			if c.IsAborted() {
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(raw))
			return
		}
		c.Next()
	}
}

// HandleQueueAgentCommand is POST /agents/:agent_id/commands
// {"kind", "args", "reason"}.
func (h *AgentAPIHandler) HandleQueueAgentCommand(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	agentID := c.Param("agent_id")
	var body struct {
		Kind   string          `json:"kind"`
		Args   json.RawMessage `json:"args"`
		Reason string          `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if _, known := agentCommandKinds[body.Kind]; !known {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind must be restart, collect_logs, reenroll, set_options, update_now or uninstall"})
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Kind == "uninstall" && len(body.Reason) < 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uninstall needs a reason of at least 10 characters"})
		return
	}
	if len(body.Reason) > 500 {
		body.Reason = body.Reason[:500]
	}
	args, msg := validCommandArgs(body.Kind, body.Args)
	if msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	ctx := c.Request.Context()
	var status string
	if err := h.db.Pool.QueryRow(ctx,
		`SELECT status FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, agentID, orgID).Scan(&status); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if status == agentStatusRevoked || status == agentStatusRetired {
		c.JSON(http.StatusConflict, gin.H{"error": "the device is " + status + "; it takes no commands"})
		return
	}
	var queued int
	// Fail closed: an unread count must not read as zero and wave a command
	// past the per-device limit.
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_commands
		WHERE org_id = $1 AND agent_id = $2 AND status IN ('queued', 'delivered')`, orgID, agentID).Scan(&queued); err != nil {
		h.logger.Error("count queued agent commands failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to queue the command"})
		return
	}
	if queued >= maxQueuedCommandsPerAgent {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "this device already has too many commands waiting"})
		return
	}
	var createdBy interface{}
	if u := c.GetString("user_id"); u != "" {
		if _, err := uuid.Parse(u); err == nil {
			createdBy = u
		}
	}
	var id string
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO agent_commands (org_id, agent_id, kind, args, reason, created_by)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6::uuid) RETURNING id::text`,
		orgID, agentID, body.Kind, args, body.Reason, createdBy).Scan(&id); err != nil {
		h.logger.Error("queue agent command failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to queue the command"})
		return
	}
	detail := "kind=" + body.Kind + " command=" + id
	if body.Reason != "" {
		detail += " reason=" + logsafe.Clean(body.Reason)
	}
	h.logAuditEvent("agent.command_queued", agentID, "success", detail)
	h.logAuditEventToDB(ctx, "agent.command_queued", agentID, "success", detail)
	c.JSON(http.StatusCreated, gin.H{"id": id, "kind": body.Kind, "status": "queued"})
}

// HandleListAgentCommands is GET /agents/:agent_id/commands, newest first.
func (h *AgentAPIHandler) HandleListAgentCommands(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	rows, err := h.db.Pool.Query(c.Request.Context(), `
		SELECT id::text, agent_id, kind, args, status, COALESCE(reason, ''), COALESCE(created_by::text, ''),
		       created_at, delivered_at, completed_at, expires_at, result,
		       COALESCE(artifact_name, ''), COALESCE(artifact_sha256, ''), COALESCE(octet_length(artifact), 0)
		  FROM agent_commands
		 WHERE org_id = $1 AND agent_id = $2
		 ORDER BY created_at DESC LIMIT 100`, orgID, c.Param("agent_id"))
	if err != nil {
		h.logger.Error("list agent commands failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list commands"})
		return
	}
	defer rows.Close()
	out := []agentCommandRecord{}
	for rows.Next() {
		var r agentCommandRecord
		var args, result []byte
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Kind, &args, &r.Status, &r.Reason, &r.CreatedBy,
			&r.CreatedAt, &r.DeliveredAt, &r.CompletedAt, &r.ExpiresAt, &result,
			&r.ArtifactName, &r.ArtifactSHA256, &r.ArtifactSize); err != nil {
			continue
		}
		if len(args) > 0 {
			r.Args = args
		}
		if len(result) > 0 {
			r.Result = result
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

// HandleAgentCommandArtifact is GET /agents/:agent_id/commands/:command_id/artifact.
func (h *AgentAPIHandler) HandleAgentCommandArtifact(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	var data []byte
	var name, sum string
	err := h.db.Pool.QueryRow(c.Request.Context(), `
		SELECT artifact, COALESCE(artifact_name, ''), COALESCE(artifact_sha256, '')
		  FROM agent_commands WHERE id::text = $1 AND agent_id = $2 AND org_id = $3`,
		c.Param("command_id"), c.Param("agent_id"), orgID).Scan(&data, &name, &sum)
	if err != nil || data == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no artifact"})
		return
	}
	if name == "" {
		name = "artifact.bin"
	}
	h.logAuditEventToDB(c.Request.Context(), "agent.command_artifact_downloaded", c.Param("agent_id"), "success",
		"command="+logsafe.Clean(c.Param("command_id")))
	c.Header("Content-Disposition", `attachment; filename="`+safeArtifactName(name)+`"`)
	c.Header("X-Content-Type-Options", "nosniff")
	if sum != "" {
		c.Header("X-Artifact-SHA256", sum)
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// HandleCancelAgentCommand is DELETE /agents/:agent_id/commands/:command_id;
// only a queued command can be cancelled.
func (h *AgentAPIHandler) HandleCancelAgentCommand(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE agent_commands SET status = 'cancelled', completed_at = NOW()
		 WHERE id::text = $1 AND agent_id = $2 AND org_id = $3 AND status = 'queued'`,
		c.Param("command_id"), c.Param("agent_id"), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cancel"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "only a queued command can be cancelled"})
		return
	}
	h.logAuditEventToDB(ctx, "agent.command_cancelled", c.Param("agent_id"), "success",
		"command="+logsafe.Clean(c.Param("command_id")))
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

// deliverAgentCommands hands an active agent its queued commands and marks
// them delivered in the same statement, so two config syncs racing never
// both receive one.
func (h *AgentAPIHandler) deliverAgentCommands(ctx context.Context, agentID string) []agentCommandDelivery {
	if h.db == nil || h.db.Pool == nil {
		return nil
	}
	rows, err := h.db.Pool.Query(ctx, `
		UPDATE agent_commands SET status = 'delivered', delivered_at = NOW()
		 WHERE id IN (SELECT id FROM agent_commands
		               WHERE agent_id = $1 AND org_id = $2 AND status = 'queued' AND expires_at > NOW()
		               ORDER BY created_at LIMIT 10 FOR UPDATE SKIP LOCKED)
		RETURNING id::text, kind, args, created_at`, agentID, orgIDFrom(ctx))
	if err != nil {
		h.logger.Warn("deliver agent commands failed", logsafe.String("agent_id", agentID), zap.Error(err))
		return nil
	}
	defer rows.Close()
	type delivered struct {
		d  agentCommandDelivery
		at time.Time
	}
	var list []delivered
	for rows.Next() {
		var d agentCommandDelivery
		var args []byte
		var at time.Time
		if rows.Scan(&d.ID, &d.Kind, &args, &at) == nil {
			if len(args) > 0 && string(args) != "{}" {
				d.Args = args
			}
			list = append(list, delivered{d, at})
		}
	}
	// RETURNING has no order; hand them over in the order they were queued.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].at.Before(list[j-1].at); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	out := make([]agentCommandDelivery, 0, len(list))
	for _, l := range list {
		out = append(out, l.d)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// HandleAgentCommandResult is POST /agent/commands/:command_id/result,
// called by the device with its own credential:
// {"status": "done|failed", "result": {...}, "artifact_b64", "artifact_name"}.
func (h *AgentAPIHandler) HandleAgentCommandResult(c *gin.Context) {
	agentID, ok := h.requireEnrolledAgent(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, maxCommandResultBody+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	if len(raw) > maxCommandResultBody {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "the artifact exceeds 8 MiB"})
		return
	}
	if !h.requireDeviceSignature(c, agentID, raw) {
		return
	}
	var body struct {
		Status       string          `json:"status"`
		Result       json.RawMessage `json:"result"`
		ArtifactB64  string          `json:"artifact_b64"`
		ArtifactName string          `json:"artifact_name"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse body"})
		return
	}
	if body.Status != "done" && body.Status != "failed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be done or failed"})
		return
	}
	if len(body.Result) > 64<<10 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "result too large"})
		return
	}
	var resultJSON interface{}
	if len(body.Result) > 0 {
		if !json.Valid(body.Result) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "result is not JSON"})
			return
		}
		resultJSON = []byte(body.Result)
	}
	var artifact []byte
	var name, sum interface{}
	if body.ArtifactB64 != "" {
		artifact, err = base64.StdEncoding.DecodeString(body.ArtifactB64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "artifact is not base64"})
			return
		}
		if len(artifact) > maxCommandArtifactBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "the artifact exceeds 8 MiB"})
			return
		}
		s := sha256.Sum256(artifact)
		sum = hex.EncodeToString(s[:])
		name = safeArtifactName(body.ArtifactName)
	}
	ctx := c.Request.Context()
	var kind string
	err = h.db.Pool.QueryRow(ctx, `
		UPDATE agent_commands
		   SET status = $1, result = $2::jsonb, completed_at = NOW(),
		       artifact = $3, artifact_name = $4, artifact_sha256 = $5
		 WHERE id::text = $6 AND agent_id = $7 AND org_id = $8 AND status = 'delivered'
		RETURNING kind`,
		body.Status, resultJSON, artifact, name, sum, c.Param("command_id"), agentID, orgIDFrom(ctx)).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		// Another device's command, one never delivered, or one answered
		// already: the same answer for each, so nothing is learned.
		c.JSON(http.StatusNotFound, gin.H{"error": "no such command awaiting a result"})
		return
	}
	if err != nil {
		h.logger.Error("store agent command result failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store the result"})
		return
	}
	detail := "kind=" + kind + " command=" + logsafe.Clean(c.Param("command_id")) + " status=" + body.Status
	h.logAuditEvent("agent.command_completed", agentID, body.Status, detail)
	h.logAuditEventToDB(ctx, "agent.command_completed", agentID, body.Status, detail)
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

// expireAgentCommands marks commands nobody finished in time as expired.
func (h *AgentAPIHandler) expireAgentCommands(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	if _, err := h.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide sweep: expiry is a property of each row's own expires_at
		`UPDATE agent_commands SET status = 'expired', completed_at = NOW()
		  WHERE status IN ('queued', 'delivered') AND expires_at <= NOW()`); err != nil {
		h.logger.Debug("expire agent commands failed", zap.Error(err))
	}
}

// safeArtifactName keeps a file name a Content-Disposition can carry.
func safeArtifactName(n string) string {
	n = filepath.Base(strings.TrimSpace(n))
	var b strings.Builder
	for _, r := range n {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "artifact.bin"
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}
