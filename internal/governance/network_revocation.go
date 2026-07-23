package governance

import (
	"context"

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
