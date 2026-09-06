// Package access — PAM C5: human-in-the-loop (HITL) approval for AI-agent tool
// calls through the MCP gateway.
//
// The MCP gateway lets AI agents invoke tools on brokered MCP servers, gated by
// a per-(principal, tool) allowlist. For SENSITIVE tools an allowlist entry can
// be marked require_approval; the gateway then does NOT forward the call
// immediately. Instead it records a pending approval bound to the exact request
// (sha256 of the body) and returns 202 with an approval id. A human approves or
// denies; the agent retries the identical call and, once approved, it forwards
// exactly once (the approval is consumed).
//
// This brings privileged-access-style four-eyes control to autonomous agents:
// low-risk tools run freely, high-risk tools (deploy, delete, pay, email) wait
// for a human, and every decision is on the audit trail.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// mcpApprovalWindow is how long a pending tool-call approval stays open.
const mcpApprovalWindow = 30 * time.Minute

// toolRequiresApproval reports whether any matching allowlist entry for this
// principal set + tool is marked require_approval. Uses the same principal
// expansion as toolAllowed.
func (s *Service) toolRequiresApproval(ctx context.Context, orgID, serverID, clientID string, roles []string, tool string) bool {
	principals := []string{"client:" + clientID}
	for _, r := range roles {
		principals = append(principals, "role:"+r)
	}
	var req bool
	if err := s.db.Pool.QueryRow(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM mcp_tool_policies
             WHERE server_id = $1 AND org_id::text = $4 AND principal = ANY($2)
               AND (tool = $3 OR tool = '*')
               AND require_approval = true)`,
		serverID, principals, tool, orgID).Scan(&req); err != nil {
		return false
	}
	return req
}

// requestHash binds an approval to one exact invocation body.
func requestHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// consumeApprovedToolCall atomically consumes an 'approved' approval matching
// this (server, tool, client, request body). Returns true when a call is
// cleared to proceed. Single-use: the row flips to 'consumed'.
func (s *Service) consumeApprovedToolCall(ctx context.Context, orgID, serverID, tool, clientID string, body []byte) (bool, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx, `
        UPDATE mcp_tool_approvals SET status = 'consumed', decided_at = COALESCE(decided_at, NOW())
         WHERE id = (
            SELECT id FROM mcp_tool_approvals
             WHERE server_id = $1 AND tool = $2 AND client_id = $3 AND request_hash = $4
               AND org_id::text = $5
               AND status = 'approved'
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY created_at DESC LIMIT 1)
           AND org_id::text = $5
         RETURNING id`,
		serverID, tool, clientID, requestHash(body), orgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// createOrGetPendingToolApproval inserts a pending approval for this exact call,
// or returns the existing pending/approved one (idempotent so an agent polling
// with the same body doesn't stack rows). Returns the approval id + status.
func (s *Service) createOrGetPendingToolApproval(ctx context.Context, orgID, serverID, tool, clientID, subject string, body []byte) (string, string, error) {
	// v118 left org_id nullable, and this INSERT used to pass it through
	// NULLIF($1,''), so a tenantless caller wrote an approval with a NULL tenant
	// — a row handleListPendingToolApprovals cannot see (it carries
	// AND a.org_id = $1), so the administrator would never be shown the request
	// and the agent would wait for a decision nobody could make. The invoke path
	// has refused a tenantless caller since requireMCPOrg landed, so no such row
	// can be written today; refusing here means it stays that way rather than
	// resting on a caller.
	if orgID == "" {
		return "", "", errors.New("mcp approval: organization context required")
	}
	rh := requestHash(body)
	var id, status string
	err := s.db.Pool.QueryRow(ctx, `
        SELECT id, status FROM mcp_tool_approvals
         WHERE server_id = $1 AND tool = $2 AND client_id = $3 AND request_hash = $4
           AND org_id::text = $5
           AND status IN ('pending','approved')
           AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY created_at DESC LIMIT 1`,
		serverID, tool, clientID, rh, orgID).Scan(&id, &status)
	if err == nil {
		return id, status, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	expires := time.Now().Add(mcpApprovalWindow)
	if err := s.db.Pool.QueryRow(ctx, `
        INSERT INTO mcp_tool_approvals (org_id, server_id, tool, client_id, subject, request_hash, status, expires_at)
        VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''), $6, 'pending', $7)
        RETURNING id`,
		orgID, serverID, tool, clientID, subject, rh, expires).Scan(&id); err != nil {
		return "", "", err
	}
	return id, "pending", nil
}

// --- admin endpoints ---

// handleListPendingToolApprovals — GET /mcp/approvals/pending (admin).
func (s *Service) handleListPendingToolApprovals(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	// mcp_tool_approvals has carried the belt since v118, so this list was
	// already scoped by the database; the explicit terms are the defence in
	// depth a background caller under orgctx.WithBypassRLS would otherwise lose.
	// The join predicate goes in the WHERE, not the ON: a tenant term on a LEFT
	// JOIN's ON filters nothing, which is the v155 lesson.
	rows, err := s.db.Pool.Query(ctx, `
        SELECT a.id, a.server_id, COALESCE(m.name,''), a.tool, a.client_id, COALESCE(a.subject,''),
               a.created_at, a.expires_at
          FROM mcp_tool_approvals a
          LEFT JOIN mcp_servers m ON m.id = a.server_id
         WHERE a.status = 'pending' AND (a.expires_at IS NULL OR a.expires_at > NOW())
           AND a.org_id = $1 AND (m.id IS NULL OR m.org_id = $1)
         ORDER BY a.created_at ASC`, org.ID)
	if err != nil {
		s.logger.Error("handleListPendingToolApprovals: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list pending approvals"})
		return
	}
	defer rows.Close()
	type item struct {
		ID        string     `json:"id"`
		ServerID  string     `json:"server_id"`
		Server    string     `json:"server"`
		Tool      string     `json:"tool"`
		ClientID  string     `json:"client_id"`
		Subject   string     `json:"subject"`
		CreatedAt time.Time  `json:"created_at"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.ServerID, &it.Server, &it.Tool, &it.ClientID,
			&it.Subject, &it.CreatedAt, &it.ExpiresAt); err != nil {
			continue
		}
		out = append(out, it)
	}
	c.JSON(http.StatusOK, gin.H{"pending": out})
}

// handleDecideToolApproval — POST /mcp/approvals/:id/:decision (admin), where
// decision is approve|deny. Atomic transition from pending.
func (s *Service) handleDecideToolApproval(c *gin.Context) {
	id := c.Param("id")
	decision := c.Param("decision")
	newStatus := ""
	switch decision {
	case "approve":
		newStatus = "approved"
	case "deny":
		newStatus = "denied"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approve or deny"})
		return
	}
	ctx := c.Request.Context()
	org, oerr := orgctx.From(ctx)
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	approver := c.GetString("user_id")

	// The organization resolved above used to be discarded, and this UPDATE
	// addressed the row by the bare id from the URL — the shape guacamole.go's
	// own comment calls "the whole security of this handler", here on the
	// approve/deny of an AI agent's tool call.
	var serverID, tool, clientID string
	err := s.db.Pool.QueryRow(ctx, `
        UPDATE mcp_tool_approvals
           SET status = $2, approver_id = $3, decided_at = NOW()
         WHERE id = $1 AND org_id::text = $4 AND status = 'pending'
           AND (expires_at IS NULL OR expires_at > NOW())
         RETURNING server_id::text, tool, client_id`,
		id, newStatus, approver, org.ID).Scan(&serverID, &tool, &clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusConflict, gin.H{"error": "approval is not pending, already decided, or expired"})
		return
	}
	if err != nil {
		s.logger.Error("handleDecideToolApproval: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record decision"})
		return
	}
	s.auditMCP(ctx, clientID, approver, serverID, tool, "approval."+decision)
	c.JSON(http.StatusOK, gin.H{"id": id, "status": newStatus})
}

// mcpApprovalContext carries the values needed to gate an invocation.
type mcpApprovalContext struct {
	OrgID    string
	ServerID string
	Server   string
	Tool     string
	ClientID string
	Subject  string
}

// gateToolCall applies the HITL approval gate. Returns (true, nil) when the
// call may proceed (either approval not required, or an approved+consumed
// approval exists). When approval is required and not yet granted it writes the
// 202/403 response itself and returns (false, nil).
func (s *Service) gateToolCall(ctx context.Context, c *gin.Context, ac mcpApprovalContext, roles []string, body []byte) (bool, error) {
	if !s.toolRequiresApproval(ctx, ac.OrgID, ac.ServerID, ac.ClientID, roles, ac.Tool) {
		return true, nil
	}
	// Already approved for this exact call? Consume and proceed.
	ok, err := s.consumeApprovedToolCall(ctx, ac.OrgID, ac.ServerID, ac.Tool, ac.ClientID, body)
	if err != nil {
		return false, err
	}
	if ok {
		return true, nil
	}
	// Otherwise open/return a pending approval.
	id, status, err := s.createOrGetPendingToolApproval(ctx, ac.OrgID, ac.ServerID, ac.Tool, ac.ClientID, ac.Subject, body)
	if err != nil {
		return false, err
	}
	if status == "approved" {
		// Race: approved between the consume attempt and now — consume again.
		if ok, _ := s.consumeApprovedToolCall(ctx, ac.OrgID, ac.ServerID, ac.Tool, ac.ClientID, body); ok {
			return true, nil
		}
	}
	s.auditMCP(ctx, ac.ClientID, ac.Subject, ac.Server, ac.Tool, "approval.pending")
	c.Header("X-MCP-Approval-Required", "true")
	c.Header("X-MCP-Approval-Id", id)
	c.JSON(http.StatusAccepted, gin.H{
		"approval_required": true,
		"approval_id":       id,
		"status":            status,
		"message":           "this tool requires human approval; retry the identical call once approved",
	})
	return false, nil
}
