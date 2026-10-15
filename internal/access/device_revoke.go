package access

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/sessionend"
)

// deviceRevoker revokes one enrolled device across every pillar: the overlay
// (its live circuits severed and its Device identity deleted), the fleet row,
// the IAM known device, and the OAuth refresh-token families and sessions
// bound to the device (v185).
//
// It is the ONE implementation. Agent Fleet's revoke, Access 360's device
// revoke and the kill switch's revoke_devices option all call it, so a device
// is revoked the same way whichever button an administrator pressed. Before
// this the fleet route set the status and deleted the identity and nothing
// else: the device's tokens went on refreshing, its known device stayed
// trusted and its live circuits were not severed -- which revoke an operator
// got depended on which page they were on.
//
// Every step is best-effort: one pillar failing is a warning in the result,
// never a reason to leave the others in place.
type deviceRevoker struct {
	db *database.PostgresDB
	// zm is the controller, or nil while it is not connected: the overlay
	// half is then deferred to the deprovision sweep, and said so.
	zm *ZitiManager
	// redis is the revocation store, or nil when none is configured: the
	// refresh grant then has only the revoked rows to go by.
	redis  *redis.Client
	logger *zap.Logger
}

// revoke performs the cross-pillar device severance.
func (r deviceRevoker) revoke(ctx context.Context, orgID, agentID, zitiIdentityID, knownDeviceID string) *DeviceRevokeResult {
	res := &DeviceRevokeResult{AgentID: agentID, ExecutedAt: time.Now().UTC()}
	safeAgentID := logsafe.Clean(agentID)
	warn := func(step string, err error) {
		r.logger.Warn("device revoke: step failed",
			zap.String("step", step), zap.String("agent_id", safeAgentID), zap.Error(err))
		res.Warnings = append(res.Warnings, step+": "+err.Error())
	}
	if r.db == nil || r.db.Pool == nil {
		res.Warnings = append(res.Warnings, "database: not configured; nothing revoked")
		return res
	}

	// Ziti: sever live circuits + delete the Device identity on the controller.
	res.ZitiControllerOnline = r.zm != nil
	if r.zm != nil && zitiIdentityID != "" {
		if edge, api, err := r.zm.TerminateIdentitySessions(ctx, zitiIdentityID); err != nil {
			warn("terminate_ziti_sessions", err)
		} else {
			res.ZitiEdgeSessions, res.ZitiAPISessions = edge, api
		}
		if err := r.zm.DeleteIdentity(ctx, zitiIdentityID); err != nil {
			warn("delete_ziti_identity", err)
		} else {
			res.ZitiIdentityDeleted = true
		}
	} else if zitiIdentityID != "" {
		res.Warnings = append(res.Warnings,
			"ziti: controller not connected — network sessions not severed (revoked agent's identity delete deferred)")
	}

	// Ziti mirror + IAM: mark the agent revoked and untrust the known device.
	if _, err := r.db.Pool.Exec(ctx,
		`UPDATE enrolled_agents SET status = 'revoked', ziti_identity_id = NULL WHERE agent_id = $1 AND org_id = $2`,
		agentID, orgID); err != nil {
		warn("revoke_agent", err)
	} else {
		res.AgentRevoked = true
	}
	if knownDeviceID != "" {
		if tag, err := r.db.Pool.Exec(ctx,
			`UPDATE known_devices SET trusted = false WHERE id = $1 AND org_id = $2`,
			knownDeviceID, orgID); err != nil {
			warn("untrust_known_device", err)
		} else if tag.RowsAffected() > 0 {
			res.KnownDeviceUntrusted = true
		}
	}

	// IAM: the tokens this device holds. See revokeTokens.
	r.revokeTokens(ctx, orgID, agentID, res, warn)

	r.logger.Info("device revoked across pillars",
		zap.String("agent_id", safeAgentID),
		zap.Bool("ziti_identity_deleted", res.ZitiIdentityDeleted),
		zap.Int("ziti_edge_sessions", res.ZitiEdgeSessions),
		zap.Bool("known_device_untrusted", res.KnownDeviceUntrusted),
		zap.Int64("refresh_tokens_revoked", res.RefreshTokensRevoked),
		zap.Int64("oauth_sessions_revoked", res.OAuthSessionsRevoked))
	return res
}

// revokeTokens severs the OAuth half of a device revoke: every refresh-token
// family bound to this agent (v185), and the login sessions those families
// ran under.
//
// WHY IT IS TWO STEPS. Revoking the refresh rows stops the device MINTING a new
// access token; the refresh grant (internal/oauth/service.go) also reads the
// revoked_session:<id> marker and the session's row, and marking the sessions
// revoked is what the console's session list reads too. A device can hold
// several chains — one per sign-in — so both sets are collected from the rows
// rather than assumed to be one.
//
// WHAT IT DOES NOT DO, said rather than implied: the access token already in the
// device's memory keeps working until it expires, because nothing on the
// request path consults the session marker — only the refresh grant does. That
// window is the client's access_token_lifetime, one hour for the native clients,
// against the thirty days it was before this existed. Closing it entirely means
// the auth middleware reading the marker on every request, which is a cost on
// every request and a change of its own.
func (r deviceRevoker) revokeTokens(ctx context.Context, orgID, agentID string, res *DeviceRevokeResult, warn func(string, error)) {
	if agentID == "" || orgID == "" {
		return
	}

	// One statement does the revoke and reports which sessions were behind it,
	// so a chain that is revoked can never fail to have its session collected.
	rows, err := r.db.Pool.Query(ctx, `
		UPDATE oauth_refresh_tokens SET revoked_at = NOW()
		 WHERE agent_id = $1 AND org_id = $2 AND revoked_at IS NULL
		 RETURNING COALESCE(session_id::text, '')`,
		agentID, orgID)
	if err != nil {
		warn("revoke_device_refresh_tokens", err)
		return
	}
	sessionIDs := map[string]struct{}{}
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			continue
		}
		res.RefreshTokensRevoked++
		if sid != "" {
			sessionIDs[sid] = struct{}{}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		warn("revoke_device_refresh_tokens", err)
	}
	if len(sessionIDs) == 0 {
		return
	}

	ids := make([]string, 0, len(sessionIDs))
	for id := range sessionIDs {
		ids = append(ids, id)
	}

	// Every other chain those sessions hold goes too, since the sessions end
	// below. A refresh token issued on one of them to another client -- an
	// application the same browser session signed into -- names no agent, so
	// the statement above did not reach it, and with only the marker behind
	// it, it went on refreshing whenever Redis was down or came back empty.
	if n, err := sessionend.RevokeRefreshTokens(ctx, r.db.Pool, orgID, ids); err != nil {
		warn("revoke_session_refresh_tokens", err)
	} else {
		res.RefreshTokensRevoked += n
	}

	// The marker is what the refresh grant honours, so publish it before the
	// row update: if the process dies between the two, a stopped session is
	// better than a session that still refreshes.
	if r.redis != nil {
		for _, id := range ids {
			if err := r.redis.Set(ctx, "revoked_session:"+id, "1", killSwitchRedisMarkerTTL).Err(); err != nil {
				warn("revocation_marker", err)
				break
			}
		}
	}

	// Captured before the rows are revoked: the relying parties the sessions
	// reached are told through backchannel_logout_pending
	// (internal/common/sessionend).
	if err := sessionend.ForSessions(ctx, r.db.Pool, orgID, ids); err != nil {
		warn("backchannel_logout_capture", err)
	}
	if tag, err := r.db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked = true, revoked_at = NOW()
		  WHERE id::text = ANY($1) AND org_id = $2 AND (revoked IS NULL OR revoked = false)`,
		ids, orgID); err != nil {
		warn("revoke_device_sessions", err)
	} else {
		res.OAuthSessionsRevoked = tag.RowsAffected()
	}
}

// deviceRevoker is the service's revoker: the controller as it is connected
// now, and the revocation store.
func (s *Service) deviceRevoker() deviceRevoker {
	var rdb *redis.Client
	if s.redis != nil && s.redis.Client != nil {
		rdb = s.redis.RevocationDB()
	}
	return deviceRevoker{db: s.db, zm: s.ziti(), redis: rdb, logger: s.logger}
}

// deviceRevoker is the agent handler's revoker, the same one the service
// uses: the controller is resolved through the service so a controller that
// connected after the handler was built is still found.
func (h *AgentAPIHandler) deviceRevoker() deviceRevoker {
	return deviceRevoker{db: h.db, zm: h.zitiManager(), redis: h.revocationRedis, logger: h.logger}
}
