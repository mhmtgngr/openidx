package oauth

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Binding a refresh-token family to the device that holds it.
//
// WHAT THIS IS FOR. Revoking a device (POST /users/:id/devices/:agentId/revoke)
// deleted the Ziti identity and terminated the overlay sessions and touched no
// OAuth token, because no row recorded which device a token belonged to. The
// native clients hold a 30-day refresh token, so a revoked phone kept acting as
// the user on every HTTP surface for a month. agent_id (v185) is the routing
// key that lets the revoke find those tokens.
//
// WHAT IT IS NOT. It is not an authentication of the device. The value arrives
// as a form parameter on the token exchange, so a client is free to omit it and
// be handed an unbound token — exactly the state before v185. That is not a
// hole this check could close: an attacker replaying a stolen refresh token
// would simply not send it. The device's real authentication lives where it
// always did — the agent credential on /agent/* (agent_auth.go) and the Ziti
// identity on the overlay.
//
// So the check here is ownership, not possession: the claimed agent must be a
// row the SERVER already records as enrolled by this same user, and not one an
// admin has revoked. A user binding their token to their own other device is
// harmless (it makes revoking that device also cut this token); binding to
// somebody else's is refused, because "revoke my phone" must not be able to cut
// a stranger's session.
//
// The Android path does not rely on the claim at all: /agent/enroll/oauth binds
// the enrolling bearer's own session to the agent the server has just issued,
// where both halves are the server's own knowledge.

// agentBindingForUser returns the agent id a refresh-token family may be bound
// to, or "" when the claim does not check out (which is not an error: the
// exchange proceeds and the family is simply unbound, as every family was
// before v185).
//
// enrolled_agents is an install-wide fleet table with no org_id — a decision
// recorded in v43, v120 and v165 — so the tenant term is the enrolling user,
// who was resolved from an org-scoped authorization code.
func (s *Service) agentBindingForUser(ctx context.Context, claimedAgentID, userID string) string {
	if claimedAgentID == "" || userID == "" || s.db == nil || s.db.Pool == nil {
		return ""
	}

	var ownerID *string
	var status string
	//orgscope:ignore enrolled_agents is a fleet table with no org_id; scoped here by the enrolling user, who came from an org-scoped authorization code
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`SELECT enrolled_by_user_id::text, COALESCE(status,'') FROM enrolled_agents WHERE agent_id = $1`,
		claimedAgentID).Scan(&ownerID, &status)
	if err != nil {
		if err != pgx.ErrNoRows {
			s.logger.Warn("device binding: agent lookup failed",
				zap.String("agent_id", logsafe.Clean(claimedAgentID)), zap.Error(err))
		}
		return ""
	}

	if ownerID == nil || *ownerID != userID {
		// Someone's client is claiming a device the server does not record as
		// theirs. Nothing is refused — the token is simply unbound — but this
		// is worth seeing, because the honest clients never produce it.
		s.logger.Warn("device binding refused: agent is not enrolled by this user",
			zap.String("agent_id", logsafe.Clean(claimedAgentID)),
			zap.String("user_id", logsafe.Clean(userID)))
		return ""
	}
	if status == "revoked" {
		// Binding here would hand a revoked device a chain that the revoke
		// which already ran cannot reach.
		s.logger.Warn("device binding refused: agent is revoked",
			zap.String("agent_id", logsafe.Clean(claimedAgentID)))
		return ""
	}

	return claimedAgentID
}
