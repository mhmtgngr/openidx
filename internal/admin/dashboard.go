// Package admin provides dashboard statistics for the admin console
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
	dashboardStatsCacheKey = "dashboard:stats"
	dashboardStatsCacheTTL = 5 * time.Minute
)

// DashboardStats contains aggregated dashboard statistics
type DashboardStats struct {
	UserCount       int64          `json:"user_count"`
	ActiveSessions  int64          `json:"active_sessions"`
	MFAAdoptionRate float64        `json:"mfa_adoption_rate"`
	RecentEvents    []SecurityEvent `json:"recent_events"`
	CachedAt        *time.Time     `json:"cached_at,omitempty"`
}

// SecurityEvent represents a recent security event from the audit log
type SecurityEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Category  string    `json:"category"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	ActorID   string    `json:"actor_id,omitempty"`
	ActorIP   string    `json:"actor_ip,omitempty"`
}

// GetDashboardStats retrieves dashboard statistics with caching
func (s *Service) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	s.logger.Debug("Fetching dashboard statistics")

	// Try to get from cache first
	cachedData, err := s.redis.Client.Get(ctx, dashboardStatsCacheKey).Result()
	if err == nil {
		s.logger.Debug("Dashboard stats cache hit")
		var stats DashboardStats
		if err := json.Unmarshal([]byte(cachedData), &stats); err != nil {
			s.logger.Warn("Failed to unmarshal cached dashboard stats", zap.Error(err))
		} else {
			return &stats, nil
		}
	} else if err != redis.Nil {
		s.logger.Warn("Redis error checking dashboard stats cache", zap.Error(err))
	}

	// Cache miss or error - fetch from database
	s.logger.Debug("Dashboard stats cache miss - aggregating from database")
	stats, err := s.aggregateDashboardStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate dashboard stats: %w", err)
	}

	// Store in cache
	data, err := json.Marshal(stats)
	if err != nil {
		s.logger.Warn("Failed to marshal dashboard stats for caching", zap.Error(err))
	} else {
		if err := s.redis.Client.Set(ctx, dashboardStatsCacheKey, data, dashboardStatsCacheTTL).Err(); err != nil {
			s.logger.Warn("Failed to cache dashboard stats", zap.Error(err))
		}
	}

	return stats, nil
}

// aggregateDashboardStats aggregates statistics from multiple sources
func (s *Service) aggregateDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// Get total user count from identity service
	var totalUsers int64
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE deleted_at IS NULL
	`).Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	stats.UserCount = totalUsers

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

	// Calculate MFA adoption rate (enabled users / total users * 100)
	if totalUsers > 0 {
		var mfaEnabledUsers int64
		err = s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(DISTINCT user_id) FROM mfa_totp WHERE enabled = true
		`).Scan(&mfaEnabledUsers)
		if err != nil {
			s.logger.Warn("Failed to count MFA enabled users", zap.Error(err))
			mfaEnabledUsers = 0
		}
		stats.MFAAdoptionRate = (float64(mfaEnabledUsers) / float64(totalUsers)) * 100.0
	}

	// Get recent security events from audit log (last 24 hours)
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, timestamp, event_type, category, action, outcome,
		       COALESCE(actor_id, ''), COALESCE(actor_ip, '')
		FROM audit_events
		WHERE timestamp >= $1
		ORDER BY timestamp DESC
		LIMIT 10
	`, twentyFourHoursAgo)
	if err != nil {
		s.logger.Warn("Failed to query recent security events", zap.Error(err))
		stats.RecentEvents = []SecurityEvent{}
	} else {
		defer rows.Close()
		events := []SecurityEvent{}
		for rows.Next() {
			var e SecurityEvent
			if err := rows.Scan(
				&e.ID, &e.Timestamp, &e.EventType, &e.Category, &e.Action, &e.Outcome,
				&e.ActorID, &e.ActorIP,
			); err != nil {
				s.logger.Warn("Failed to scan security event row", zap.Error(err))
				continue
			}
			events = append(events, e)
		}
		stats.RecentEvents = events
	}

	// Set cache timestamp
	now := time.Now()
	stats.CachedAt = &now

	s.logger.Debug("Dashboard stats aggregated successfully",
		zap.Int64("user_count", stats.UserCount),
		zap.Int64("active_sessions", stats.ActiveSessions),
		zap.Float64("mfa_adoption_rate", stats.MFAAdoptionRate),
		zap.Int("recent_events", len(stats.RecentEvents)),
	)

	return stats, nil
}

// handleGetDashboardStats handles GET /api/v1/admin/dashboard/stats
func (s *Service) handleGetDashboardStats(c *gin.Context) {
	stats, err := s.GetDashboardStats(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to get dashboard stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve dashboard statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}
