package identity

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
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

func (s *Service) cleanupExpiredRoles(ctx context.Context) {
	result, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore background ticker sweep of expired role assignments across all orgs; no request/tenant context
		`DELETE FROM user_roles
		WHERE expires_at IS NOT NULL AND expires_at < NOW()`)
	if err != nil {
		s.logger.Error("Failed to cleanup expired roles", zap.Error(err))
		return
	}
	if result.RowsAffected() > 0 {
		s.logger.Info("Cleaned up expired role assignments",
			zap.Int64("count", result.RowsAffected()))
	}
}
