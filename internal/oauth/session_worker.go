// Package oauth provides background session lifecycle management
package oauth

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// StartSessionWorker starts a background goroutine that periodically checks for
// expired or idle sessions and revokes them. It runs every 60 seconds.
func (s *Service) StartSessionWorker(ctx context.Context) {
	s.logger.Info("Starting session expiry worker")

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("Session expiry worker stopped")
				return
			case <-ticker.C:
				s.processExpiredSessions(ctx)
			}
		}
	}()
}

// processExpiredSessions finds and revokes sessions that have exceeded their timeouts
func (s *Service) processExpiredSessions(ctx context.Context) {
	// Load global session policy (we process all sessions with global defaults)
	policy := s.getEffectiveSessionPolicy(ctx, "")

	// Phase 1: Revoke sessions past their expires_at (absolute expiry set at creation)
	expiredRows, err := s.db.Pool.Query(ctx, `
		SELECT id FROM sessions
		WHERE (revoked IS NULL OR revoked = false)
		AND expires_at <= NOW()
		LIMIT 500
	`)
	if err != nil {
		s.logger.Error("Failed to query expired sessions", zap.Error(err))
	} else {
		var expiredCount int
		for expiredRows.Next() {
			var sessionID string
			if scanErr := expiredRows.Scan(&sessionID); scanErr != nil {
				continue
			}
			if revokeErr := s.revokeSessionWithRedis(ctx, sessionID); revokeErr != nil {
				s.logger.Error("Failed to revoke expired session",
					zap.String("session_id", sessionID), zap.Error(revokeErr))
			} else {
				expiredCount++
			}
		}
		expiredRows.Close()
		if expiredCount > 0 {
			s.logger.Info("Revoked expired sessions", zap.Int("count", expiredCount))
		}
	}

	// Phase 2: Revoke sessions that have been idle too long (based on global policy)
	if policy.IdleTimeout > 0 {
		idleCutoff := time.Now().Add(-time.Duration(policy.IdleTimeout) * time.Second)
		idleRows, err := s.db.Pool.Query(ctx, `
			SELECT id FROM sessions
			WHERE (revoked IS NULL OR revoked = false)
			AND expires_at > NOW()
			AND last_seen_at < $1
			LIMIT 500
		`, idleCutoff)
		if err != nil {
			s.logger.Error("Failed to query idle sessions", zap.Error(err))
		} else {
			var idleCount int
			for idleRows.Next() {
				var sessionID string
				if scanErr := idleRows.Scan(&sessionID); scanErr != nil {
					continue
				}
				if revokeErr := s.revokeSessionWithRedis(ctx, sessionID); revokeErr != nil {
					s.logger.Error("Failed to revoke idle session",
						zap.String("session_id", sessionID), zap.Error(revokeErr))
				} else {
					idleCount++
				}
			}
			idleRows.Close()
			if idleCount > 0 {
				s.logger.Info("Revoked idle sessions", zap.Int("count", idleCount))
			}
		}
	}

	// Phase 3: Clean up stale Redis revocation keys for sessions that are already old
	// Redis TTL handles this automatically via the 25-hour expiry set in revokeSessionWithRedis
}
