// Package admin provides enhanced dashboard statistics for the admin console
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	enhancedDashboardStatsCacheKey = "dashboard:stats:enhanced"
	enhancedDashboardCacheTTL      = 5 * time.Minute
)

// EnhancedDashboardStats contains aggregated dashboard statistics with the required fields
type EnhancedDashboardStats struct {
	TotalUsers        int64           `json:"total_users"`
	ActiveUsers24h    int64           `json:"active_users_24h"`
	MFAAdoptionPct    float64         `json:"mfa_adoption_pct"`
	ActiveSessions    int64           `json:"active_sessions"`
	FailedLogins24h   int64           `json:"failed_logins_24h"`
	AvgRiskScore      float64         `json:"avg_risk_score"`
	TopRiskEvents     []RiskEvent     `json:"top_risk_events"`
	LoginSuccessRate  float64         `json:"login_success_rate"`
	CachedAt          *time.Time      `json:"cached_at,omitempty"`
}

// RiskEvent represents a high-risk security event
type RiskEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	RiskScore     int       `json:"risk_score"`
	ActorID       string    `json:"actor_id,omitempty"`
	ActorIP       string    `json:"actor_ip,omitempty"`
	Reason        string    `json:"reason"`
}

// GetEnhancedDashboardStats retrieves enhanced dashboard statistics with caching.
// Aggregates data from identity, audit, and risk services via internal API calls.
func (s *Service) GetEnhancedDashboardStats(ctx context.Context) (*EnhancedDashboardStats, error) {
	s.logger.Debug("Fetching enhanced dashboard statistics")

	// Try to get from cache first
	cachedData, err := s.redis.Client.Get(ctx, enhancedDashboardStatsCacheKey).Result()
	if err == nil {
		s.logger.Debug("Enhanced dashboard stats cache hit")
		var stats EnhancedDashboardStats
		if err := json.Unmarshal([]byte(cachedData), &stats); err != nil {
			s.logger.Warn("Failed to unmarshal cached enhanced dashboard stats", zap.Error(err))
		} else {
			return &stats, nil
		}
	} else if err != redis.Nil {
		s.logger.Warn("Redis error checking enhanced dashboard stats cache", zap.Error(err))
	}

	// Cache miss or error - fetch from database
	s.logger.Debug("Enhanced dashboard stats cache miss - aggregating from database")
	stats, err := s.aggregateEnhancedDashboardStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate enhanced dashboard stats: %w", err)
	}

	// Store in cache
	data, err := json.Marshal(stats)
	if err != nil {
		s.logger.Warn("Failed to marshal enhanced dashboard stats for caching", zap.Error(err))
	} else {
		if err := s.redis.Client.Set(ctx, enhancedDashboardStatsCacheKey, data, enhancedDashboardCacheTTL).Err(); err != nil {
			s.logger.Warn("Failed to cache enhanced dashboard stats", zap.Error(err))
		}
	}

	return stats, nil
}

// aggregateEnhancedDashboardStats aggregates statistics from multiple sources
func (s *Service) aggregateEnhancedDashboardStats(ctx context.Context) (*EnhancedDashboardStats, error) {
	stats := &EnhancedDashboardStats{}
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)

	// Get total user count from identity service (users table)
	var totalUsers int64
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE deleted_at IS NULL
	`).Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	stats.TotalUsers = totalUsers

	// Get active users in last 24 hours (users with login activity)
	var activeUsers24h int64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_id) FROM audit_events
		WHERE event_type = 'authentication'
		AND action IN ('login', 'login_mfa')
		AND outcome = 'success'
		AND timestamp >= $1
	`, twentyFourHoursAgo).Scan(&activeUsers24h)
	if err != nil {
		s.logger.Warn("Failed to count active users 24h", zap.Error(err))
		activeUsers24h = 0
	}
	stats.ActiveUsers24h = activeUsers24h

	// Calculate MFA adoption rate (enabled users / total users * 100)
	if totalUsers > 0 {
		var mfaEnabledUsers int64
		err = s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true
			UNION
			SELECT COUNT(DISTINCT user_id) FROM mfa_backup_codes WHERE used = false
		`).Scan(&mfaEnabledUsers)
		if err != nil {
			s.logger.Warn("Failed to count MFA enabled users", zap.Error(err))
			mfaEnabledUsers = 0
		}
		stats.MFAAdoptionPct = (float64(mfaEnabledUsers) / float64(totalUsers)) * 100.0
	}

	// Get active session count from sessions table
	var activeSessions int64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE expires_at > NOW()
		AND (revoked IS NULL OR revoked = false)
	`).Scan(&activeSessions)
	if err != nil {
		return nil, fmt.Errorf("failed to count active sessions: %w", err)
	}
	stats.ActiveSessions = activeSessions

	// Get failed logins in last 24 hours
	var failedLogins24h int64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND outcome = 'failure'
		AND timestamp >= $1
	`, twentyFourHoursAgo).Scan(&failedLogins24h)
	if err != nil {
		s.logger.Warn("Failed to count failed logins", zap.Error(err))
		failedLogins24h = 0
	}
	stats.FailedLogins24h = failedLogins24h

	// Get average risk score from risk assessments
	var avgRiskScore float64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(risk_score), 0) FROM user_risk_scores
		WHERE assessed_at > NOW() - INTERVAL '7 days'
	`).Scan(&avgRiskScore)
	if err != nil {
		s.logger.Warn("Failed to get average risk score", zap.Error(err))
		avgRiskScore = 0
	}
	stats.AvgRiskScore = avgRiskScore

	// Get top 10 risk events (high score events from audit log with risk data)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ae.id, ae.timestamp, ae.event_type, COALESCE(ae.actor_id, ''),
		       COALESCE(ae.actor_ip, ''), COALESCE(urs.risk_score, 0),
		       COALESCE(ae.action, 'unknown')
		FROM audit_events ae
		LEFT JOIN user_risk_scores urs ON ae.actor_id = urs.user_id
		WHERE ae.timestamp >= $1
		AND (urs.risk_score >= 70 OR ae.outcome = 'failure')
		ORDER BY urs.risk_score DESC, ae.timestamp DESC
		LIMIT 10
	`, twentyFourHoursAgo)
	if err != nil {
		s.logger.Warn("Failed to query top risk events", zap.Error(err))
		stats.TopRiskEvents = []RiskEvent{}
	} else {
		defer rows.Close()
		events := []RiskEvent{}
		for rows.Next() {
			var e RiskEvent
			var reason string
			if err := rows.Scan(
				&e.ID, &e.Timestamp, &e.EventType, &e.ActorID, &e.ActorIP, &e.RiskScore, &reason,
			); err != nil {
				s.logger.Warn("Failed to scan risk event row", zap.Error(err))
				continue
			}
			// Build reason from event type and risk score
			e.Reason = fmt.Sprintf("%s (risk score: %d)", e.EventType, e.RiskScore)
			events = append(events, e)
		}
		stats.TopRiskEvents = events
	}

	// Calculate login success rate (last 24h)
	var successfulLogins int64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication'
		AND action IN ('login', 'login_mfa')
		AND outcome = 'success'
		AND timestamp >= $1
	`, twentyFourHoursAgo).Scan(&successfulLogins)
	if err != nil {
		s.logger.Warn("Failed to count successful logins", zap.Error(err))
		successfulLogins = 0
	}

	totalLoginAttempts := successfulLogins + failedLogins24h
	if totalLoginAttempts > 0 {
		stats.LoginSuccessRate = (float64(successfulLogins) / float64(totalLoginAttempts)) * 100.0
	} else {
		stats.LoginSuccessRate = 100.0 // No failures if no attempts
	}

	// Set cache timestamp
	now := time.Now()
	stats.CachedAt = &now

	s.logger.Debug("Enhanced dashboard stats aggregated successfully",
		zap.Int64("total_users", stats.TotalUsers),
		zap.Int64("active_users_24h", stats.ActiveUsers24h),
		zap.Float64("mfa_adoption_pct", stats.MFAAdoptionPct),
		zap.Int64("active_sessions", stats.ActiveSessions),
		zap.Int64("failed_logins_24h", stats.FailedLogins24h),
		zap.Float64("avg_risk_score", stats.AvgRiskScore),
		zap.Int("top_risk_events", len(stats.TopRiskEvents)),
		zap.Float64("login_success_rate", stats.LoginSuccessRate),
	)

	return stats, nil
}

// handleGetEnhancedDashboardStats handles GET /api/v1/admin/dashboard
func (s *Service) handleGetEnhancedDashboardStats(c *gin.Context) {
	stats, err := s.GetEnhancedDashboardStats(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to get enhanced dashboard stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve enhanced dashboard statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// InvalidateEnhancedDashboardCache invalidates the dashboard cache (call after data changes)
func (s *Service) InvalidateEnhancedDashboardCache(ctx context.Context) error {
	return s.redis.Client.Del(ctx, enhancedDashboardStatsCacheKey).Err()
}
