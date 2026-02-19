package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// LoginAnomaly represents a high-risk or anomalous login event
type LoginAnomaly struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	Username          string    `json:"username"`
	IPAddress         string    `json:"ip_address"`
	Location          string    `json:"location"`
	RiskScore         int       `json:"risk_score"`
	Success           bool      `json:"success"`
	AuthMethods       []string  `json:"auth_methods"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	CreatedAt         time.Time `json:"created_at"`
}

// UserRiskProfile represents a user's risk baseline and recent login activity
type UserRiskProfile struct {
	UserID            string          `json:"user_id"`
	Username          string          `json:"username"`
	TypicalLoginHours json.RawMessage `json:"typical_login_hours"`
	TypicalCountries  json.RawMessage `json:"typical_countries"`
	TypicalIPs        json.RawMessage `json:"typical_ips"`
	AvgRiskScore      float64         `json:"avg_risk_score"`
	LoginCount        int             `json:"login_count"`
	LastUpdatedAt     *time.Time      `json:"last_updated_at"`
	RecentLogins      []LoginAnomaly  `json:"recent_logins"`
}

// RiskOverview provides aggregate risk statistics across all logins
type RiskOverview struct {
	TotalLogins      int            `json:"total_logins"`
	HighRiskLogins   int            `json:"high_risk_logins"`
	AvgRiskScore     float64        `json:"avg_risk_score"`
	FailedLogins     int            `json:"failed_logins"`
	UniqueUsers      int            `json:"unique_users"`
	RiskDistribution map[string]int `json:"risk_distribution"`
}

// handleLoginAnomalies returns high-risk login events from login_history.
// GET /api/v1/risk/anomalies?min_score=40&limit=50&offset=0&days=7
func (s *Service) handleLoginAnomalies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	minScore := 40
	if v := c.Query("min_score"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			minScore = parsed
		}
	}

	limit := 50
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 200 {
		limit = 200
	}

	offset := 0
	if v := c.Query("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	days := 7
	if v := c.Query("days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT lh.id, lh.user_id, u.username, lh.ip_address,
		       COALESCE(lh.location, '') as location, lh.risk_score, lh.success,
		       COALESCE(lh.auth_methods, '{}') as auth_methods,
		       COALESCE(lh.device_fingerprint, '') as device_fingerprint,
		       lh.created_at
		FROM login_history lh
		JOIN users u ON u.id = lh.user_id
		WHERE lh.risk_score >= $1 AND lh.created_at > NOW() - make_interval(days => $2)
		ORDER BY lh.risk_score DESC, lh.created_at DESC
		LIMIT $3 OFFSET $4
	`, minScore, days, limit, offset)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to query login anomalies", err))
		return
	}
	defer rows.Close()

	anomalies := []LoginAnomaly{}
	for rows.Next() {
		var a LoginAnomaly
		if err := rows.Scan(
			&a.ID, &a.UserID, &a.Username, &a.IPAddress,
			&a.Location, &a.RiskScore, &a.Success,
			&a.AuthMethods, &a.DeviceFingerprint,
			&a.CreatedAt,
		); err != nil {
			s.logger.Error("Failed to scan login anomaly row", zap.Error(err))
			continue
		}
		anomalies = append(anomalies, a)
	}

	c.JSON(http.StatusOK, gin.H{"data": anomalies})
}

// handleUserRiskProfile returns a user's risk baseline and recent login history.
// GET /api/v1/risk/profiles/:id
func (s *Service) handleUserRiskProfile(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	userID := c.Param("id")

	var profile UserRiskProfile
	profile.UserID = userID

	err := s.db.Pool.QueryRow(ctx, `
		SELECT urb.user_id, u.username, urb.typical_login_hours, urb.typical_countries,
		       urb.typical_ips, urb.avg_risk_score, urb.login_count, urb.last_updated_at
		FROM user_risk_baselines urb
		JOIN users u ON u.id = urb.user_id
		WHERE urb.user_id = $1
	`, userID).Scan(
		&profile.UserID, &profile.Username,
		&profile.TypicalLoginHours, &profile.TypicalCountries,
		&profile.TypicalIPs, &profile.AvgRiskScore,
		&profile.LoginCount, &profile.LastUpdatedAt,
	)
	if err != nil {
		// If no baseline exists, populate defaults and try to get the username
		s.logger.Debug("No risk baseline found for user, using defaults", zap.String("user_id", userID), zap.Error(err))
		profile.TypicalLoginHours = json.RawMessage("[]")
		profile.TypicalCountries = json.RawMessage("[]")
		profile.TypicalIPs = json.RawMessage("[]")
		profile.AvgRiskScore = 0
		profile.LoginCount = 0
		profile.LastUpdatedAt = nil

		// Try to get the username
		_ = s.db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id = $1`, userID).Scan(&profile.Username)
	}

	// Fetch the last 10 login_history entries for this user
	loginRows, err := s.db.Pool.Query(ctx, `
		SELECT lh.id, lh.user_id, u.username, lh.ip_address,
		       COALESCE(lh.location, '') as location, lh.risk_score, lh.success,
		       COALESCE(lh.auth_methods, '{}') as auth_methods,
		       COALESCE(lh.device_fingerprint, '') as device_fingerprint,
		       lh.created_at
		FROM login_history lh
		JOIN users u ON u.id = lh.user_id
		WHERE lh.user_id = $1
		ORDER BY lh.created_at DESC
		LIMIT 10
	`, userID)
	if err != nil {
		s.logger.Error("Failed to query user login history", zap.Error(err), zap.String("user_id", userID))
		profile.RecentLogins = []LoginAnomaly{}
	} else {
		defer loginRows.Close()
		recentLogins := []LoginAnomaly{}
		for loginRows.Next() {
			var a LoginAnomaly
			if err := loginRows.Scan(
				&a.ID, &a.UserID, &a.Username, &a.IPAddress,
				&a.Location, &a.RiskScore, &a.Success,
				&a.AuthMethods, &a.DeviceFingerprint,
				&a.CreatedAt,
			); err != nil {
				s.logger.Error("Failed to scan user login row", zap.Error(err))
				continue
			}
			recentLogins = append(recentLogins, a)
		}
		profile.RecentLogins = recentLogins
	}

	c.JSON(http.StatusOK, profile)
}

// handleRiskOverview returns aggregate risk statistics from login_history.
// GET /api/v1/risk/overview
func (s *Service) handleRiskOverview(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	var overview RiskOverview

	err := s.db.Pool.QueryRow(ctx, `
		SELECT
		    COUNT(*) as total_logins,
		    SUM(CASE WHEN risk_score >= 50 THEN 1 ELSE 0 END) as high_risk_logins,
		    COALESCE(AVG(risk_score), 0) as avg_risk_score,
		    SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed_logins,
		    COUNT(DISTINCT user_id) as unique_users
		FROM login_history
		WHERE created_at > NOW() - INTERVAL '7 days'
	`).Scan(
		&overview.TotalLogins,
		&overview.HighRiskLogins,
		&overview.AvgRiskScore,
		&overview.FailedLogins,
		&overview.UniqueUsers,
	)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to query risk overview", err))
		return
	}

	// Compute risk distribution by score ranges
	distribution := map[string]int{
		"low":      0,
		"medium":   0,
		"high":     0,
		"critical": 0,
	}

	distRows, err := s.db.Pool.Query(ctx, `
		SELECT
		    CASE
		        WHEN risk_score < 20 THEN 'low'
		        WHEN risk_score >= 20 AND risk_score < 40 THEN 'medium'
		        WHEN risk_score >= 40 AND risk_score < 70 THEN 'high'
		        ELSE 'critical'
		    END as risk_level,
		    COUNT(*) as cnt
		FROM login_history
		WHERE created_at > NOW() - INTERVAL '7 days'
		GROUP BY risk_level
	`)
	if err != nil {
		s.logger.Error("Failed to query risk distribution", zap.Error(err))
	} else {
		defer distRows.Close()
		for distRows.Next() {
			var level string
			var cnt int
			if distRows.Scan(&level, &cnt) == nil {
				distribution[level] = cnt
			}
		}
	}
	overview.RiskDistribution = distribution

	c.JSON(http.StatusOK, overview)
}
