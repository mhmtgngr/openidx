package access

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Claiming a fleet-enrolled device without a wizard (Faz B8.3).
//
// A device enrolled with a fleet token (Intune, GPO, a script) names no one:
// enrolled_by_user_id is NULL, so it shows as "unclaimed" and never reaches
// anyone's My Devices. Two ways give it an owner without a person opening the
// console's Add a device page:
//
//	login           the tray's "Sign in" ends by calling POST /agent/claim
//	                with BOTH credentials: the device's own (X-Agent-ID +
//	                X-Auth-Token) and the person's access token (Authorization).
//	                The device must be active, ownerless and in the person's
//	                organization. This is always on.
//	logged_on_user  when the organization opts in (org_agent_settings), the
//	                service's report names the Windows session user, and an
//	                ownerless device becomes that person's when the name is a
//	                directory- or federation-sourced user of the organization.
//	                A local account is never matched: the directory is the
//	                authority on who a UPN is, a name typed into OpenIDX is not.

const (
	claimModeLogin        = "login"
	claimModeLoggedOnUser = "logged_on_user"
)

// claimUserSources are the users.source values the logged_on_user mode may
// match. Anything else (local, manual, a self sign-up) is a name the
// directory does not vouch for.
var claimUserSources = []string{"ldap", "scim", "saml", "oidc", "federated", "azure_ad", "entra", "google", "hris"}

// HandleClaimAgent is POST /agent/claim.
func (h *AgentAPIHandler) HandleClaimAgent(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sign in first"})
		return
	}
	userOrg, _ := orgctx.From(c.Request.Context())
	agentID, token := strings.TrimSpace(c.GetHeader("X-Agent-ID")), strings.TrimSpace(c.GetHeader("X-Auth-Token"))
	agentOrg, status, ok := verifyEnrolledAgent(c.Request.Context(), h.db, agentID, token)
	if status == agentStatusRevoked {
		refuseRevokedAgent(c, h, agentOrg, agentID)
		return
	}
	if !ok {
		h.logAuditEvent("agent.auth_failed", agentID, "denied", "invalid agent credentials (claim)")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent credentials"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	// The person and the device must be in the same organization. A user of
	// another tenant holding this device's credential is not its owner.
	if userOrg.ID == "" || agentOrg != userOrg.ID {
		ctx := orgctx.With(c.Request.Context(), orgctx.Org{ID: agentOrg})
		detail := "claim refused: the signed-in user belongs to another organization (user=" + logsafe.Clean(userID) + ")"
		h.logAuditEvent("agent.claim_denied", agentID, "denied", detail)
		h.logAuditEventToDB(ctx, "agent.claim_denied", agentID, "denied", detail)
		c.JSON(http.StatusForbidden, gin.H{"error": "this device belongs to another organization", "code": "agent_other_org"})
		return
	}
	ctx := orgctx.With(c.Request.Context(), orgctx.Org{ID: agentOrg})
	res, err := h.claimAgent(ctx, agentID, agentOrg, userID)
	switch {
	case err != nil:
		h.logger.Error("agent claim failed", logsafe.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to claim the device"})
		return
	case res.ownedByOther:
		detail := "claim refused: the device belongs to another user (user=" + logsafe.Clean(userID) + ")"
		h.logAuditEvent("agent.claim_denied", agentID, "denied", detail)
		h.logAuditEventToDB(ctx, "agent.claim_denied", agentID, "denied", detail)
		c.JSON(http.StatusConflict, gin.H{
			"error": "device belongs to another user",
			"code":  "agent_owned_by_another_user",
			"error_description": "this device is enrolled to another person in this organization; " +
				"an administrator can move it to you",
		})
		return
	case res.notActive:
		c.JSON(http.StatusConflict, gin.H{"error": "the device is not active", "code": "agent_not_active"})
		return
	}

	// The tray's session is the one that claimed: revoking the device revokes
	// it. Same two steps an OAuth enrolment ends with.
	h.linkAgentToKnownDevice(ctx, c.ClientIP(), agentID, res.deviceID, userID, agentOrg,
		enrollRequest{Hostname: res.hostname, Platform: res.platform}, false)
	h.bindSessionTokensToAgent(ctx, c.GetString("session_id"), userID, agentOrg, agentID)

	if res.claimed {
		detail := "method=login user=" + logsafe.Clean(userID)
		h.logAuditEvent("agent.claimed", agentID, "success", detail)
		h.logAuditEventToDB(ctx, "agent.claimed", agentID, "success", detail)
	}
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "owner_user_id": userID, "claimed": res.claimed})
}

type claimResult struct {
	claimed      bool // this call set the owner (false: it was already this user's)
	ownedByOther bool
	notActive    bool
	deviceID     string
	hostname     string
	platform     string
}

// claimAgent sets userID as the owner of an active, ownerless agent. The
// owner test is in the UPDATE, so two people signing in at once cannot both
// win: the loser reads the winner's id and is refused.
func (h *AgentAPIHandler) claimAgent(ctx context.Context, agentID, orgID, userID string) (claimResult, error) {
	var r claimResult
	err := h.db.Pool.QueryRow(ctx, `
		UPDATE enrolled_agents SET enrolled_by_user_id = $3::uuid
		 WHERE agent_id = $1 AND org_id = $2 AND status = 'active' AND enrolled_by_user_id IS NULL
		RETURNING device_id, COALESCE(metadata->>'hostname',''), COALESCE(platform,'')`,
		agentID, orgID, userID).Scan(&r.deviceID, &r.hostname, &r.platform)
	if err == nil {
		r.claimed = true
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return r, err
	}
	var owner, status string
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(enrolled_by_user_id::text,''), status, device_id,
		       COALESCE(metadata->>'hostname',''), COALESCE(platform,'')
		  FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`,
		agentID, orgID).Scan(&owner, &status, &r.deviceID, &r.hostname, &r.platform); err != nil {
		return r, err
	}
	switch {
	case owner != "" && !strings.EqualFold(owner, userID):
		r.ownedByOther = true
	case status != "active":
		r.notActive = true
	}
	return r, nil
}

// claimModeFor is the organization's claim_mode; login when it has no row.
func (h *AgentAPIHandler) claimModeFor(ctx context.Context, orgID string) string {
	if h.db == nil || h.db.Pool == nil || orgID == "" {
		return claimModeLogin
	}
	var mode string
	if err := h.db.Pool.QueryRow(ctx,
		`SELECT claim_mode FROM org_agent_settings WHERE org_id = $1`, orgID).Scan(&mode); err != nil {
		return claimModeLogin
	}
	return mode
}

// claimByLoggedOnUser makes an ownerless agent the logged-on user's, when
// the organization runs logged_on_user and the name resolves to exactly one
// directory- or federation-sourced, enabled user of the organization.
// Best-effort: the report has been accepted whatever this does.
func (h *AgentAPIHandler) claimByLoggedOnUser(ctx context.Context, clientIP, agentID, logonName string) {
	orgID := orgIDFrom(ctx)
	name := normalizeLogonName(logonName)
	if name == "" || orgID == "" || h.db == nil || h.db.Pool == nil {
		return
	}
	if h.claimModeFor(ctx, orgID) != claimModeLoggedOnUser {
		return
	}
	rows, err := h.db.Pool.Query(ctx, `
		SELECT id::text FROM users
		 WHERE org_id = $1 AND enabled = true AND source = ANY($3)
		   AND (lower(email) = $2 OR lower(username) = $2)
		 LIMIT 2`, orgID, name, claimUserSources)
	if err != nil {
		h.logger.Warn("logged-on user claim: user lookup failed", zap.Error(err))
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) != 1 {
		return // no directory user by that name, or two: claim nothing
	}
	res, err := h.claimAgent(ctx, agentID, orgID, ids[0])
	if err != nil || !res.claimed {
		return
	}
	h.linkAgentToKnownDevice(ctx, clientIP, agentID, res.deviceID, ids[0], orgID,
		enrollRequest{Hostname: res.hostname, Platform: res.platform}, false)
	detail := "method=logged_on_user user=" + logsafe.Clean(ids[0])
	h.logAuditEvent("agent.claimed", agentID, "success", detail)
	h.logAuditEventToDB(ctx, "agent.claimed", agentID, "success", detail)
}

// normalizeLogonName lowercases a UPN and drops a DOMAIN\ prefix, so
// "CORP\alice" and "Alice@corp.example" are compared as the directory stores
// them. Empty for anything that is not a plausible single name.
func normalizeLogonName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if s == "" || len(s) > 320 || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	return s
}

// HandleGetAgentSettings is GET /agent/settings.
func (h *AgentAPIHandler) HandleGetAgentSettings(c *gin.Context) {
	ctx := c.Request.Context()
	c.JSON(http.StatusOK, gin.H{"claim_mode": h.claimModeFor(ctx, orgIDFrom(ctx))})
}

// HandleUpdateAgentSettings is PUT /agent/settings.
func (h *AgentAPIHandler) HandleUpdateAgentSettings(c *gin.Context) {
	var body struct {
		ClaimMode string `json:"claim_mode"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if body.ClaimMode != claimModeLogin && body.ClaimMode != claimModeLoggedOnUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "claim_mode must be login or logged_on_user"})
		return
	}
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	if h.db == nil || h.db.Pool == nil || orgID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var updatedBy interface{}
	if u := c.GetString("user_id"); u != "" {
		updatedBy = u
	}
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO org_agent_settings (org_id, claim_mode, updated_by, updated_at)
		VALUES ($1, $2, $3::uuid, NOW())
		ON CONFLICT (org_id) DO UPDATE
		   SET claim_mode = EXCLUDED.claim_mode, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		orgID, body.ClaimMode, updatedBy); err != nil {
		h.logger.Error("agent settings update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save the settings"})
		return
	}
	h.logAuditEvent("agent.settings_updated", "", "success", "claim_mode="+body.ClaimMode)
	h.logAuditEventToDB(ctx, "agent.settings_updated", "", "success", "claim_mode="+body.ClaimMode)
	c.JSON(http.StatusOK, gin.H{"claim_mode": body.ClaimMode})
}
