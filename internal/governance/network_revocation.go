package governance

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// enqueueNetworkRevocation records a circuit-severance intent for the given
// user. The governance service has no Ziti access, so it hands off to the
// access-service (which owns the ZitiManager) via network_revocation_queue; a
// worker there terminates the user's live overlay circuits. Best-effort: a
// failure is logged and never fails the revoke (the DB assignment removal +
// attribute reconcile already deny new dials; this only severs live ones).
func (s *Service) enqueueNetworkRevocation(ctx context.Context, userID, orgID, reason string) {
	if userID == "" {
		return
	}
	_, err := s.db.Pool.Exec(ctx, `
        INSERT INTO network_revocation_queue (org_id, user_id, reason)
        VALUES (NULLIF($1,'')::uuid, $2::uuid, $3)`,
		orgID, userID, reason)
	if err != nil {
		s.logger.Warn("failed to enqueue network revocation",
			zap.String("user_id", sanitizeForLog(userID)), zap.String("reason", reason), zap.Error(err))
	}
}

// enqueueNetworkGrant records a JIT network-grant intent (Wave B1): the
// access-service worker adds the time-bound Ziti role attribute to the user's
// identity, opening the dial. Best-effort; a failure is logged.
func (s *Service) enqueueNetworkGrant(ctx context.Context, userID, orgID, requestID, attribute string, expiresAt *time.Time) {
	if userID == "" || attribute == "" {
		return
	}
	_, err := s.db.Pool.Exec(ctx, `
        INSERT INTO network_grant_queue (org_id, user_id, request_id, attribute, expires_at)
        VALUES (NULLIF($1,'')::uuid, $2::uuid, NULLIF($3,'')::uuid, $4, $5)`,
		orgID, userID, requestID, attribute, expiresAt)
	if err != nil {
		s.logger.Warn("failed to enqueue network grant",
			zap.String("user_id", sanitizeForLog(userID)), zap.String("attribute", sanitizeForLog(attribute)), zap.Error(err))
	}
}

// enqueueNetworkAttributeRemoval records an intent to REMOVE a specific JIT
// attribute (and sever the resulting orphaned circuits) on grant expiry.
func (s *Service) enqueueNetworkAttributeRemoval(ctx context.Context, userID, orgID, attribute, reason string) {
	if userID == "" || attribute == "" {
		return
	}
	_, err := s.db.Pool.Exec(ctx, `
        INSERT INTO network_revocation_queue (org_id, user_id, reason, attribute)
        VALUES (NULLIF($1,'')::uuid, $2::uuid, $3, $4)`,
		orgID, userID, reason, attribute)
	if err != nil {
		s.logger.Warn("failed to enqueue network attribute removal",
			zap.String("user_id", sanitizeForLog(userID)), zap.String("attribute", sanitizeForLog(attribute)), zap.Error(err))
	}
}

// jitNetworkAttribute is the deterministic Ziti role attribute for a JIT network
// grant, derived from the request id so a grant and its expiry name the same
// attribute. Ziti role attributes are lowercase, dash-separated tokens.
func jitNetworkAttribute(requestID string) string {
	return "jit-" + requestID
}
