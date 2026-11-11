package access

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Agent identity continuity (Faz B8.4, v252).
//
// One machine is one agent row while it is in use, and the administrator has
// the lifecycle moves that keep it that way:
//
//	PUT  /agents/:id/owner      the device changes hands: a new owner, the
//	                            known-device link moved to them.
//	POST /agents/:id/reinstate  a revoke is lifted: the row is left pending
//	                            with a credential nobody holds, so the device
//	                            enrols again (by its fleet token or a code) and
//	                            keeps its agent id, history and tags.
//	POST /agents/:id/retire     the device leaves the fleet for good: its
//	                            overlay identity is deleted, its fingerprint is
//	                            freed (the v252 key excludes retired rows), so
//	                            the machine enrolling again is a new row.
//	DELETE /agents/:id?purge=1  a retired row and its posture history go.
//
// Each is operator tier with fresh MFA (RegisterAgentAdminRoutes).

// agentStatusRetired is the status POST /agents/:id/retire writes.
const agentStatusRetired = "retired"

// gateWhenPurging applies gate only to a DELETE /agents/:id?purge=1, so a
// plain revoke is never interrupted for a second factor and an irreversible
// delete always is.
func gateWhenPurging(gate gin.HandlerFunc) gin.HandlerFunc {
	if gate == nil {
		return nil
	}
	return func(c *gin.Context) {
		if c.Query("purge") == "1" {
			gate(c)
			return
		}
		c.Next()
	}
}

// fleetOrg reads the caller's organization, answering 403 when there is none.
func (h *AgentAPIHandler) fleetOrg(c *gin.Context) (string, bool) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return "", false
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil || org.ID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return "", false
	}
	return org.ID, true
}

// unheldTokenHash is the hash of a credential nobody is given, written where a
// device's old credential must stop working.
func unheldTokenHash() string { return sha256Hex(uuid.New().String() + uuid.New().String()) }

// HandleReassignAgentOwner is PUT /agents/:agent_id/owner {"user_id": "..."}.
// The new owner must be an enabled user of the same organization. The device's
// known-device link moves to them (untrusted until the device next reports),
// and the old owner's link is untrusted: it is no longer their device.
func (h *AgentAPIHandler) HandleReassignAgentOwner(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	agentID := c.Param("agent_id")
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.UserID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	newOwner := strings.TrimSpace(body.UserID)
	if _, err := uuid.Parse(newOwner); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is not a user id"})
		return
	}
	ctx := c.Request.Context()

	var enabled bool
	if err := h.db.Pool.QueryRow(ctx,
		`SELECT enabled FROM users WHERE id = $1::uuid AND org_id = $2`, newOwner, orgID).Scan(&enabled); err != nil || !enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "no enabled user with that id in this organization"})
		return
	}

	var deviceID, hostname, platform, status, oldKnown string
	err := h.db.Pool.QueryRow(ctx, `
		SELECT device_id, COALESCE(NULLIF(hostname,''), metadata->>'hostname', ''),
		       COALESCE(platform, ''), status, COALESCE(known_device_id::text, '')
		  FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, agentID, orgID).
		Scan(&deviceID, &hostname, &platform, &status, &oldKnown)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if err != nil {
		h.logger.Error("reassign owner: read agent", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reassign owner"})
		return
	}
	if status == agentStatusRetired {
		c.JSON(http.StatusConflict, gin.H{"error": "a retired device has no owner to change"})
		return
	}

	actor := c.GetString("user_id")
	var actorArg interface{}
	if _, perr := uuid.Parse(actor); perr == nil {
		actorArg = actor
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET enrolled_by_user_id = $3::uuid, owner_changed_by = $4::uuid, owner_changed_at = NOW()
		 WHERE agent_id = $1 AND org_id = $2`, agentID, orgID, newOwner, actorArg); err != nil {
		h.logger.Error("reassign owner: update agent", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reassign owner"})
		return
	}
	if oldKnown != "" {
		if _, err := h.db.Pool.Exec(ctx,
			`UPDATE known_devices SET trusted = false WHERE id = $1::uuid AND org_id = $2`, oldKnown, orgID); err != nil {
			h.logger.Warn("reassign owner: untrust the old known device", zap.Error(err))
		}
	}
	h.linkAgentToKnownDevice(ctx, c.ClientIP(), agentID, deviceID, newOwner, orgID,
		enrollRequest{Hostname: hostname, Platform: platform}, false)

	detail := "owner reassigned to " + newOwner
	h.logAuditEvent("agent.owner_changed", agentID, "success", detail)
	h.logAuditEventToDB(ctx, "agent.owner_changed", agentID, "success", detail)
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "owner_user_id": newOwner})
}

// HandleReinstateAgent is POST /agents/:agent_id/reinstate. It lifts an
// administrator's revoke: the row becomes pending with a credential nobody
// holds, which the device's next enrolment (fleet token, code, OAuth) turns
// back into an active one on the same agent id. Only a revoked device can be
// reinstated.
func (h *AgentAPIHandler) HandleReinstateAgent(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	agentID := c.Param("agent_id")
	ctx := c.Request.Context()
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET status = 'pending', reinstated_at = NOW(), auth_token_hash = $3,
		       auth_fail_count = 0, auth_failed_at = NULL
		 WHERE agent_id = $1 AND org_id = $2 AND status = $4`,
		agentID, orgID, unheldTokenHash(), agentStatusRevoked)
	if err != nil {
		h.logger.Error("reinstate agent", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reinstate agent"})
		return
	}
	if tag.RowsAffected() == 0 {
		h.answerNotInState(c, ctx, agentID, orgID, "only a revoked device can be reinstated")
		return
	}
	h.logAuditEvent("agent.reinstated", agentID, "success", "admin action")
	h.logAuditEventToDB(ctx, "agent.reinstated", agentID, "success", "admin action")
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "status": "pending",
		"next": "enrol the device again (Add a device, or the fleet token installer); a device that never saw the revoke re-enrols itself from its fleet token"})
}

// HandleRetireAgent is POST /agents/:agent_id/retire. The device leaves the
// fleet for good: sessions and overlay identity go as on a revoke, its known
// device is untrusted, and its fingerprint is free, so the same machine
// enrolling later is a new row. The token hash stays so the device still
// proves who it is and is answered 403 like a revoked one: the agent then
// forgets its sealed fleet token instead of enrolling itself back in.
func (h *AgentAPIHandler) HandleRetireAgent(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	agentID := c.Param("agent_id")
	ctx := c.Request.Context()

	var zitiID, knownID, status string
	err := h.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(ziti_identity_id, ''), COALESCE(known_device_id::text, ''), status
		  FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, agentID, orgID).
		Scan(&zitiID, &knownID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if err != nil {
		h.logger.Error("retire agent: read", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retire agent"})
		return
	}
	if status == agentStatusRetired {
		c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "status": agentStatusRetired})
		return
	}
	// The full revoke first (sessions, identity, tokens, device trust), then
	// the row is marked retired.
	if h.revokeDevice != nil {
		h.revokeDevice(ctx, orgID, agentID, zitiID, knownID)
	} else if h.zm != nil && zitiID != "" {
		if delErr := h.zm.DeleteIdentity(ctx, zitiID); delErr != nil {
			h.logger.Warn("retire agent: delete Ziti identity", logsafe.String("agent_id", agentID), zap.Error(delErr))
		}
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET status = $3, retired_at = NOW(), ziti_identity_id = NULL
		 WHERE agent_id = $1 AND org_id = $2`, agentID, orgID, agentStatusRetired); err != nil {
		h.logger.Error("retire agent: update", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retire agent"})
		return
	}
	if knownID != "" {
		if _, err := h.db.Pool.Exec(ctx,
			`UPDATE known_devices SET trusted = false WHERE id = $1::uuid AND org_id = $2`, knownID, orgID); err != nil {
			h.logger.Warn("retire agent: untrust known device", zap.Error(err))
		}
	}
	h.logAuditEvent("agent.retired", agentID, "success", "admin action")
	h.logAuditEventToDB(ctx, "agent.retired", agentID, "success", "admin action")
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "status": agentStatusRetired})
}

// purgeRetiredAgent is DELETE /agents/:agent_id?purge=1: a retired device's row
// and its posture history are deleted. Any other status is refused 409; retire
// it first.
func (h *AgentAPIHandler) purgeRetiredAgent(c *gin.Context, agentID string) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to purge agent"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`DELETE FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2 AND status = $3`,
		agentID, orgID, agentStatusRetired)
	if err != nil {
		h.logger.Error("purge agent", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to purge agent"})
		return
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		h.answerNotInState(c, ctx, agentID, orgID, "only a retired device can be purged; retire it first")
		return
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM agent_posture_results WHERE agent_id = $1 AND org_id = $2`, agentID, orgID); err != nil {
		h.logger.Error("purge agent posture", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to purge agent"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to purge agent"})
		return
	}
	h.logAuditEvent("agent.purged", agentID, "success", "admin action")
	h.logAuditEventToDB(ctx, "agent.purged", agentID, "success", "admin action")
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "status": "purged", "purged_at": time.Now().UTC()})
}

// answerNotInState answers a conditional update that matched nothing: 404 when
// the agent is not in this organization, 409 with why otherwise.
func (h *AgentAPIHandler) answerNotInState(c *gin.Context, ctx context.Context, agentID, orgID, why string) {
	var one int
	if err := h.db.Pool.QueryRow(ctx,
		`SELECT 1 FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, agentID, orgID).Scan(&one); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusConflict, gin.H{"error": why})
}

// agentIsRetired reports whether agentID in orgID is retired. A retired row is
// never revoked: that would put its fingerprint back under the key.
func (h *AgentAPIHandler) agentIsRetired(ctx context.Context, agentID, orgID string) bool {
	var status string
	if err := h.db.Pool.QueryRow(ctx,
		`SELECT status FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, agentID, orgID).Scan(&status); err != nil {
		return false
	}
	return status == agentStatusRetired
}

// HandleSetAgentTags is PUT /agents/:agent_id/tags {"tags": [...]}: the
// device's labels, replaced. Tags target posture checks (v255) and filter
// the fleet list (?tag=). Operator tier.
func (h *AgentAPIHandler) HandleSetAgentTags(c *gin.Context) {
	orgID, ok := h.fleetOrg(c)
	if !ok {
		return
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	tags, err := normalizeTokenTags(body.Tags)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sort.Strings(tags)
	agentID := c.Param("agent_id")
	ctx := c.Request.Context()
	tag, err := h.db.Pool.Exec(ctx,
		`UPDATE enrolled_agents SET tags = $3::text[] WHERE agent_id = $1 AND org_id = $2`, agentID, orgID, tags)
	if err != nil {
		h.logger.Error("set agent tags failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save the tags"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	detail := "tags=" + logsafe.Clean(strings.Join(tags, ","))
	h.logAuditEvent("agent.tags_updated", agentID, "success", detail)
	h.logAuditEventToDB(ctx, "agent.tags_updated", agentID, "success", detail)
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "tags": tags})
}
