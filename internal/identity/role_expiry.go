package identity

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
)

// StartRoleExpirationChecker starts a background goroutine that periodically
// cleans up expired role assignments from the user_roles table.
func (s *Service) StartRoleExpirationChecker(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Role expiration checker started")

	// Leader-gated: clean up expired role assignments once per interval
	// cluster-wide.
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "identity:role-expiry", 1*time.Minute, s.cleanupExpiredRoles)
}

// cleanupExpiredRoles removes role assignments whose expires_at has passed AND
// cuts the tokens that still carry them.
//
// THE ELEVATION USED TO OUTLIVE ITS OWN EXPIRY. `expires_at` is this product's
// time-bound elevation: somebody is made an admin until 15:00. At 15:00 this
// sweep deleted the row, logged a count, and stopped -- and the enforcement
// point never looked at the row. `PermissionResolver` takes the caller's role
// list from the JWT `roles` claim, not from `user_roles`, so the access token
// minted at 14:00 kept saying "admin" and kept being believed until it expired
// on its own. The grant had a deadline; the credential carrying it did not.
//
// Clearing the permission cache cannot fix this and is not attempted: that
// cache is keyed on (org, ROLE SET), so the entry this user's token resolves to
// is the entry every genuine holder of that role resolves to. It is correct for
// them. What has to change is the token, and the per-user revocation marker is
// the one thing the enforcement point reads for that.
//
// RETURNING user_id, for the reason the stale-account cleanup needed it: a
// sweep that cuts BY PREDICATE has no identities to revoke. `RowsAffected` is a
// number, and a number cannot be revoked.
//
// Best-effort and loud on the revoke, the contract every sever path here
// shares: the assignment is already gone when this runs, so a Redis hiccup must
// not make the sweep retry a deletion it already did -- but "the elevation was
// removed and its token was not cut" is exactly what an operator needs in the
// record.
func (s *Service) cleanupExpiredRoles(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background ticker sweep of expired role assignments across all orgs; no request/tenant context
		`DELETE FROM user_roles
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		RETURNING user_id::text`)
	if err != nil {
		s.logger.Error("Failed to cleanup expired roles", zap.Error(err))
		return
	}

	var expired []string
	for rows.Next() {
		var userID string
		if scanErr := rows.Scan(&userID); scanErr != nil {
			// Keep going: the rows are already deleted, and an id we failed to
			// read is an id we cannot revoke -- which is the thing to say out
			// loud rather than a reason to abandon the ones we did read.
			s.logger.Error("expired role assignment removed but its user could not be read; that token will not be cut",
				zap.Error(scanErr))
			continue
		}
		expired = append(expired, userID)
	}
	rows.Close()
	if rerr := rows.Err(); rerr != nil {
		s.logger.Error("the expired-role list is incomplete; some elevations were removed without their tokens being cut",
			zap.Error(rerr), zap.Int("revocable", len(expired)))
	}
	if len(expired) == 0 {
		return
	}

	// Distinct: one user can hold several assignments that expire on the same
	// tick, and the marker is per user, not per assignment.
	seen := make(map[string]struct{}, len(expired))
	revoked := 0
	for _, userID := range expired {
		if _, dup := seen[userID]; dup {
			continue
		}
		seen[userID] = struct{}{}
		if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
			s.logger.Error("a time-bound role expired, but the tokens still carrying it were not revoked",
				logsafe.String("user_id", userID), zap.Error(err))
			continue
		}
		revoked++
	}

	s.logger.Info("Cleaned up expired role assignments",
		zap.Int("count", len(expired)),
		zap.Int("users_revoked", revoked))
}
