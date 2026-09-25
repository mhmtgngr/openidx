// Package oauth provides background session lifecycle management
package oauth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// StartSessionWorker starts a background goroutine that periodically checks for
// expired or idle sessions and revokes them. It runs every 60 seconds.
func (s *Service) StartSessionWorker(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Starting session expiry worker")

	// Leader-gated: across replicas this sweep runs once per interval
	// cluster-wide (avoids revoking each session N times).
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "oauth:session-expiry", 60*time.Second, s.processExpiredSessions)
}

// processExpiredSessions finds and revokes sessions that have exceeded their timeouts
func (s *Service) processExpiredSessions(ctx context.Context) {
	// Load global session policy (we process all sessions with global defaults)
	policy := s.getEffectiveSessionPolicy(ctx, "")

	// Phase 1: Revoke sessions past their expires_at (absolute expiry set at creation)
	expiredRows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background ticker sweeping expired sessions across all orgs; no request/tenant context
		`SELECT id FROM sessions
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

	// Phase 1b: the absolute timeout, counted from sign-in. expires_at is not
	// that bound: the refresh grant's activity update pushes it forward on
	// every refresh, so it measures how long a session has been left alone.
	// The Security tab's absolute timeout was shown and read by nothing; while
	// that activity update was lost, the 24 hours every session is created
	// with happened to stand in for it.
	if policy.AbsoluteTimeout > 0 {
		cutoff := time.Now().Add(-time.Duration(policy.AbsoluteTimeout) * time.Second)
		s.revokeSessionsWhere(ctx, "absolute timeout",
			//orgscope:ignore background ticker sweeping sessions past the absolute timeout across all orgs; no request/tenant context
			`SELECT id FROM sessions
			WHERE (revoked IS NULL OR revoked = false)
			AND started_at <= $1
			LIMIT 500
		`, cutoff)
	}

	// Phase 2: Revoke sessions that have been idle too long (based on global policy)
	if policy.IdleTimeout > 0 {
		idleCutoff := time.Now().Add(-time.Duration(policy.IdleTimeout) * time.Second)
		idleRows, err := s.db.Pool.Query(ctx,
			//orgscope:ignore background ticker sweeping idle sessions across all orgs; no request/tenant context
			`SELECT id FROM sessions
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

	// Phase 3: Clean up expired SAML sessions so the saml_sessions bookkeeping
	// table stays bounded once SLO sessions age out.
	if err := s.cleanupExpiredSAMLSessions(ctx); err != nil {
		s.logger.Error("Failed to clean up expired SAML sessions", zap.Error(err))
	}

	// Phase 4: Clean up stale Redis revocation keys for sessions that are already old
	// Redis TTL handles this automatically via the 25-hour expiry set in revokeSessionWithRedis
}

// revokeSessionsWhere ends every session the query selects (one id column),
// through the same funnel as the other phases, and logs how many.
func (s *Service) revokeSessionsWhere(ctx context.Context, why, query string, args ...interface{}) {
	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("Failed to query sessions to end", zap.String("reason", why), zap.Error(err))
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
	ended := 0
	for _, id := range ids {
		if err := s.revokeSessionWithRedis(ctx, id); err != nil {
			s.logger.Error("Failed to end session", zap.String("reason", why),
				zap.String("session_id", id), zap.Error(err))
			continue
		}
		ended++
	}
	if ended > 0 {
		s.logger.Info("Ended sessions", zap.String("reason", why), zap.Int("count", ended))
	}
}
