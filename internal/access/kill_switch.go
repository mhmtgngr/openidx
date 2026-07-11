// Package access — cross-pillar kill switch.
//
// The unified-store counterpart to the access map: one admin action that
// severs a user's live access across all three pillars at once —
//
//	IAM:  revoke identity sessions (+ Redis revocation markers the
//	      oauth-service honors on every refresh grant),
//	PAM:  revoke active vault checkouts, expire direct vault grants, revoke
//	      JIT elevations, terminate live Guacamole sessions,
//	Ziti: terminate the identity's edge + API sessions on the controller
//	      (severing live circuits), for the user identity and any device
//	      identities the user enrolled.
//
// With disable_user=true the account is also disabled and the user's Ziti
// identity is deleted immediately (the 30s deprovision sweep would otherwise
// pick it up on the next tick).
//
// Every step is best-effort and idempotent: one pillar failing must not stop
// the others from being severed. The response reports exactly what happened.
package access

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// killSwitchRedisMarkerTTL mirrors identity's revokedSessionTTL: markers must
// outlive the longest refresh-token lifetime.
const killSwitchRedisMarkerTTL = 30 * 24 * time.Hour

// KillSwitchResult reports what the kill switch severed, per pillar.
type KillSwitchResult struct {
	UserID               string    `json:"user_id"`
	Username             string    `json:"username"`
	UserDisabled         bool      `json:"user_disabled"`
	SessionsRevoked      int64     `json:"iam_sessions_revoked"`
	APIKeysRevoked       int64     `json:"iam_api_keys_revoked"`
	CheckoutsRevoked     int64     `json:"pam_checkouts_revoked"`
	VaultGrantsExpired   int64     `json:"pam_vault_grants_expired"`
	JITGrantsRevoked     int64     `json:"pam_jit_grants_revoked"`
	GuacSessionsKilled   int       `json:"pam_privileged_sessions_terminated"`
	ZitiEdgeSessions     int       `json:"ziti_edge_sessions_terminated"`
	ZitiAPISessions      int       `json:"ziti_api_sessions_terminated"`
	ZitiIdentityDeleted  bool      `json:"ziti_identity_deleted"`
	ZitiControllerOnline bool      `json:"ziti_controller_online"`
	Warnings             []string  `json:"warnings,omitempty"`
	ExecutedAt           time.Time `json:"executed_at"`
}

// handleUserKillSwitch severs one user's live access across IAM, PAM and Ziti.
// POST /api/v1/access/users/:id/kill-switch (admin)
//
// Body: {"reason": "...", "disable_user": bool}
func (s *Service) handleUserKillSwitch(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")

	var req struct {
		Reason      string `json:"reason"`
		DisableUser bool   `json:"disable_user"`
	}
	_ = c.ShouldBindJSON(&req) // both fields optional

	username, _, err := s.verifyOrgUser(ctx, org.ID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	actorID, _ := c.Get("user_id")
	actorIDStr, _ := actorID.(string)
	if actorIDStr == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refusing to kill-switch your own account"})
		return
	}

	result := s.executeKillSwitch(ctx, org.ID, userID, username, actorIDStr, req.Reason, req.DisableUser)

	// Cross-pillar audit: one unified event carrying the full severance
	// summary, visible in the same stream as the ziti/guacamole activity it
	// terminated.
	if s.auditService != nil {
		details := map[string]interface{}{
			"actor_id":                       actorIDStr,
			"reason":                         req.Reason,
			"user_disabled":                  result.UserDisabled,
			"iam_sessions_revoked":           result.SessionsRevoked,
			"iam_api_keys_revoked":           result.APIKeysRevoked,
			"pam_checkouts_revoked":          result.CheckoutsRevoked,
			"pam_vault_grants_expired":       result.VaultGrantsExpired,
			"pam_jit_grants_revoked":         result.JITGrantsRevoked,
			"pam_privileged_sessions_killed": result.GuacSessionsKilled,
			"ziti_edge_sessions_terminated":  result.ZitiEdgeSessions,
			"ziti_api_sessions_terminated":   result.ZitiAPISessions,
			"ziti_identity_deleted":          result.ZitiIdentityDeleted,
		}
		if err := s.auditService.RecordEvent(ctx, "openidx", "user.kill_switch", "", userID, c.ClientIP(), details); err != nil {
			s.logger.Warn("kill-switch: unified audit write failed", zap.Error(err))
		}
	}
	s.logAuditEvent(c, "user_kill_switch", userID, "user", map[string]interface{}{
		"reason":       req.Reason,
		"disable_user": req.DisableUser,
	})

	c.JSON(http.StatusOK, result)
}

// executeKillSwitch runs the three-pillar severance. Each step is best-effort:
// failures are collected as warnings, never abort the remaining pillars.
func (s *Service) executeKillSwitch(ctx context.Context, orgID, userID, username, actorID, reason string, disableUser bool) *KillSwitchResult {
	res := &KillSwitchResult{
		UserID:     userID,
		Username:   username,
		ExecutedAt: time.Now().UTC(),
	}
	safeUserID := scrubLogValue(userID)
	warn := func(step string, err error) {
		s.logger.Warn("kill-switch: step failed",
			zap.String("step", step), zap.String("user_id", safeUserID), zap.Error(err))
		res.Warnings = append(res.Warnings, step+": "+err.Error())
	}

	// ---- IAM: disable first (blocks new logins before we sever live state) ----
	if disableUser {
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2`,
			userID, orgID); err != nil {
			warn("disable_user", err)
		} else {
			res.UserDisabled = true
		}
	}

	// Collect live session ids, publish the cross-service revocation markers
	// (same contract as identity's deprovisionUser), then revoke the rows.
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id FROM sessions WHERE user_id = $1 AND org_id = $2
		  AND (revoked IS NULL OR revoked = false)`, userID, orgID)
	if err != nil {
		warn("list_sessions", err)
	} else {
		var sessionIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				sessionIDs = append(sessionIDs, id)
			}
		}
		rows.Close()
		if s.redis != nil {
			for _, id := range sessionIDs {
				if err := s.redis.Client.Set(ctx, "revoked_session:"+id, "1", killSwitchRedisMarkerTTL).Err(); err != nil {
					warn("revocation_marker", err)
					break
				}
			}
		}
	}
	if tag, err := s.db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked = true, revoked_at = NOW()
		  WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false)`,
		userID, orgID); err != nil {
		warn("revoke_sessions", err)
	} else {
		res.SessionsRevoked = tag.RowsAffected()
	}

	// API keys are standing credentials, not live sessions — they are revoked
	// only when the account itself is being disabled.
	if disableUser {
		if tag, err := s.db.Pool.Exec(ctx,
			`UPDATE api_keys SET status = 'revoked' WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
			userID, orgID); err != nil {
			warn("revoke_api_keys", err)
		} else {
			res.APIKeysRevoked = tag.RowsAffected()
		}
	}

	// ---- PAM: leases, direct grants, JIT elevations, live sessions ----
	if tag, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_checkouts SET status = 'revoked', returned_at = NOW()
		  WHERE principal_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID); err != nil {
		warn("revoke_vault_checkouts", err)
	} else {
		res.CheckoutsRevoked = tag.RowsAffected()
	}
	if tag, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_access_grants SET expires_at = NOW()
		  WHERE principal_type = 'user' AND principal_id = $1 AND org_id = $2
		    AND (expires_at IS NULL OR expires_at > NOW())`,
		userID, orgID); err != nil {
		warn("expire_vault_grants", err)
	} else {
		res.VaultGrantsExpired = tag.RowsAffected()
	}
	if tag, err := s.db.Pool.Exec(ctx,
		`UPDATE jit_grants SET status = 'revoked', revoked_at = NOW(), updated_at = NOW(),
		        revoked_by = CASE WHEN $3 <> '' THEN $3::uuid ELSE revoked_by END
		  WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID, actorID); err != nil {
		warn("revoke_jit_grants", err)
	} else {
		res.JITGrantsRevoked = tag.RowsAffected()
	}

	res.GuacSessionsKilled = s.terminateUserGuacSessions(ctx, orgID, userID, warn)

	// ---- Ziti: sever live circuits on the controller ----
	zm := s.ziti()
	res.ZitiControllerOnline = zm != nil

	// The user's own (User-type) identity, plus any device identities from
	// agents this user enrolled.
	var zitiIDs []string
	var userZitiRowID, userZitiID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, ziti_id FROM ziti_identities WHERE user_id = $1 AND org_id = $2`,
		userID, orgID).Scan(&userZitiRowID, &userZitiID)
	if err == nil && userZitiID != "" {
		zitiIDs = append(zitiIDs, userZitiID)
	}
	//orgscope:ignore enrolled_agents is scoped through the org-verified enrolled_by_user_id key
	agentRows, err := s.db.Pool.Query(ctx,
		`SELECT ziti_identity_id FROM enrolled_agents
		  WHERE enrolled_by_user_id = $1 AND ziti_identity_id IS NOT NULL AND ziti_identity_id <> ''`,
		userID)
	if err != nil {
		warn("list_device_identities", err)
	} else {
		for agentRows.Next() {
			var zid string
			if err := agentRows.Scan(&zid); err == nil && zid != "" {
				zitiIDs = append(zitiIDs, zid)
			}
		}
		agentRows.Close()
	}

	if zm != nil {
		for _, zid := range zitiIDs {
			edge, api, err := zm.TerminateIdentitySessions(ctx, zid)
			res.ZitiEdgeSessions += edge
			res.ZitiAPISessions += api
			if err != nil {
				warn("terminate_ziti_sessions", err)
			}
		}
		// Disabling the account = full network deprovision, immediately rather
		// than on the next 30s sweep tick. Device identities are left in place
		// (their sessions are severed above): a device may be re-assigned, and
		// the posture/agent lifecycle owns its teardown.
		if disableUser && userZitiID != "" {
			if err := zm.DeleteIdentity(ctx, userZitiID); err != nil {
				warn("delete_ziti_identity", err)
			} else {
				if _, err := s.db.Pool.Exec(ctx,
					`DELETE FROM ziti_identities WHERE id = $1 AND org_id = $2`,
					userZitiRowID, orgID); err != nil {
					warn("delete_ziti_identity_row", err)
				}
				res.ZitiIdentityDeleted = true
			}
		}
	} else if len(zitiIDs) > 0 {
		res.Warnings = append(res.Warnings,
			"ziti: controller not connected — network sessions not severed (deprovision sweep will reconcile once connected)")
	}

	s.logger.Info("kill-switch executed",
		zap.String("user_id", safeUserID),
		zap.String("actor_id", scrubLogValue(actorID)),
		zap.String("reason", scrubLogValue(reason)),
		zap.Bool("disable_user", disableUser),
		zap.Int64("sessions_revoked", res.SessionsRevoked),
		zap.Int64("checkouts_revoked", res.CheckoutsRevoked),
		zap.Int("guac_sessions_killed", res.GuacSessionsKilled),
		zap.Int("ziti_edge_sessions", res.ZitiEdgeSessions),
		zap.Int("ziti_api_sessions", res.ZitiAPISessions))

	return res
}

// terminateUserGuacSessions force-terminates the user's active Guacamole
// sessions via the Guacamole API and marks the tracking rows. Rows are only
// marked terminated after the controller call succeeds (or when Guacamole is
// unreachable about a session it no longer knows), so the DB never claims a
// termination that didn't happen.
func (s *Service) terminateUserGuacSessions(ctx context.Context, orgID, userID string, warn func(string, error)) int {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, COALESCE(guac_session_uuid, '') FROM guacamole_sessions
		  WHERE user_id = $1 AND org_id = $2 AND status = 'active'`, userID, orgID)
	if err != nil {
		warn("list_guac_sessions", err)
		return 0
	}
	type sess struct{ rowID, uuid string }
	var sessions []sess
	for rows.Next() {
		var g sess
		if err := rows.Scan(&g.rowID, &g.uuid); err == nil {
			sessions = append(sessions, g)
		}
	}
	rows.Close()

	if len(sessions) == 0 {
		return 0
	}
	if s.guacamoleClient == nil {
		warn("terminate_guac_sessions",
			errGuacNotConfigured)
		return 0
	}

	killed := 0
	for _, g := range sessions {
		if g.uuid != "" {
			if err := s.guacamoleClient.TerminateSession(ctx, g.uuid); err != nil {
				warn("terminate_guac_session", err)
				continue
			}
		}
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE guacamole_sessions SET status = 'terminated', ended_at = NOW()
			  WHERE id = $1 AND org_id = $2 AND status = 'active'`, g.rowID, orgID); err != nil {
			warn("mark_guac_session", err)
			continue
		}
		killed++
	}
	return killed
}

var errGuacNotConfigured = &accessMapError{"guacamole not configured; active privileged sessions were not terminated"}

// TerminateIdentitySessions deletes all edge sessions and API sessions the
// controller holds for one Ziti identity, severing live circuits and forcing
// re-authentication. Returns the number of each terminated.
func (zm *ZitiManager) TerminateIdentitySessions(ctx context.Context, identityZitiID string) (edgeTerminated, apiTerminated int, err error) {
	edgeTerminated = zm.terminateSessionsAt(ctx, "/edge/management/v1/sessions", identityZitiID)
	apiTerminated = zm.terminateSessionsAt(ctx, "/edge/management/v1/api-sessions", identityZitiID)
	return edgeTerminated, apiTerminated, nil
}

// terminateSessionsAt lists a controller session collection and deletes every
// entry belonging to the given identity. Matching is done client-side (the
// payload may carry identity as an embedded object or a flat identityId),
// mirroring handleBatchDeleteZitiSessions.
func (zm *ZitiManager) terminateSessionsAt(ctx context.Context, collection, identityZitiID string) int {
	respData, statusCode, err := zm.MgmtRequest("GET", collection+"?limit=500", nil)
	if err != nil || statusCode != http.StatusOK {
		zm.logger.Warn("kill-switch: session list failed",
			zap.String("collection", collection), zap.Int("status", statusCode), zap.Error(err))
		return 0
	}

	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return 0
	}

	terminated := 0
	for _, raw := range resp.Data {
		var entry struct {
			ID         string          `json:"id"`
			Identity   json.RawMessage `json:"identity,omitempty"`
			IdentityID string          `json:"identityId,omitempty"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		matched := entry.IdentityID
		if matched == "" && len(entry.Identity) > 0 {
			var ident struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(entry.Identity, &ident) == nil {
				matched = ident.ID
			}
		}
		if matched != identityZitiID {
			continue
		}
		_, sc, delErr := zm.MgmtRequest("DELETE", collection+"/"+entry.ID, nil)
		if delErr == nil && (sc == http.StatusOK || sc == http.StatusNoContent) {
			terminated++
		}
	}
	return terminated
}
