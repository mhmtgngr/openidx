package identity

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// StartRoleExpirationChecker starts a background goroutine that periodically
// cleans up expired role assignments from the user_roles table.
func (s *Service) StartRoleExpirationChecker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		s.logger.Info("Role expiration checker started")
		for {
			select {
			case <-ctx.Done():
				s.logger.Info("Role expiration checker stopped")
				return
			case <-ticker.C:
				s.cleanupExpiredRoles(ctx)
			}
		}
	}()
}

func (s *Service) cleanupExpiredRoles(ctx context.Context) {
	result, err := s.db.Pool.Exec(ctx, `
		DELETE FROM user_roles
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
	`)
	if err != nil {
		s.logger.Error("Failed to cleanup expired roles", zap.Error(err))
		return
	}
	if result.RowsAffected() > 0 {
		s.logger.Info("Cleaned up expired role assignments",
			zap.Int64("count", result.RowsAffected()))
	}
}
