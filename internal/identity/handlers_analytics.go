package identity

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// LoginAnalytics contains comprehensive login statistics
type LoginAnalytics struct {
	Period          string                   `json:"period"`
	StartDate       time.Time                `json:"start_date"`
	EndDate         time.Time                `json:"end_date"`
	Summary         LoginSummary             `json:"summary"`
	DailyTrends     []DailyLoginStats        `json:"daily_trends"`
	HourlyPattern   []HourlyStats            `json:"hourly_pattern"`
	GeoDistribution []GeoLoginStats          `json:"geo_distribution"`
	RiskDistribution []RiskBucketStats       `json:"risk_distribution"`
	AuthMethods     []AuthMethodStats        `json:"auth_methods"`
	TopFailedUsers  []FailedUserStats        `json:"top_failed_users"`
	DeviceTypes     []DeviceTypeStats        `json:"device_types"`
}

type LoginSummary struct {
	TotalLogins         int     `json:"total_logins"`
	SuccessfulLogins    int     `json:"successful_logins"`
	FailedLogins        int     `json:"failed_logins"`
	UniqueUsers         int     `json:"unique_users"`
	NewDevices          int     `json:"new_devices"`
	HighRiskLogins      int     `json:"high_risk_logins"`
	MFAChallenges       int     `json:"mfa_challenges"`
	AverageRiskScore    float64 `json:"average_risk_score"`
	TrustedBrowserLogins int    `json:"trusted_browser_logins"`
}

type DailyLoginStats struct {
	Date       string `json:"date"`
	Successful int    `json:"successful"`
	Failed     int    `json:"failed"`
	HighRisk   int    `json:"high_risk"`
}

type HourlyStats struct {
	Hour       int `json:"hour"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type GeoLoginStats struct {
	Country    string `json:"country"`
	City       string `json:"city"`
	Count      int    `json:"count"`
	Failed     int    `json:"failed"`
	AvgRisk    float64 `json:"avg_risk"`
}

type RiskBucketStats struct {
	Bucket string `json:"bucket"`
	Min    int    `json:"min"`
	Max    int    `json:"max"`
	Count  int    `json:"count"`
}

type AuthMethodStats struct {
	Method string `json:"method"`
	Count  int    `json:"count"`
}

type FailedUserStats struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	FailedCount int    `json:"failed_count"`
	LastAttempt string `json:"last_attempt"`
}

type DeviceTypeStats struct {
	DeviceType string `json:"device_type"`
	Browser    string `json:"browser"`
	Count      int    `json:"count"`
}

// handleGetLoginAnalytics returns comprehensive login analytics
func (s *Service) handleGetLoginAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")

	var startDate, endDate time.Time
	endDate = time.Now()

	switch period {
	case "24h":
		startDate = endDate.Add(-24 * time.Hour)
	case "7d":
		startDate = endDate.AddDate(0, 0, -7)
	case "30d":
		startDate = endDate.AddDate(0, 0, -30)
	case "90d":
		startDate = endDate.AddDate(0, 0, -90)
	default:
		startDate = endDate.AddDate(0, 0, -7)
	}

	ctx := c.Request.Context()
	analytics := LoginAnalytics{
		Period:    period,
		StartDate: startDate,
		EndDate:   endDate,
	}

	// Summary stats
	analytics.Summary = s.getLoginSummary(ctx, startDate, endDate)

	// Daily trends
	analytics.DailyTrends = s.getDailyLoginTrends(ctx, startDate, endDate)

	// Hourly pattern
	analytics.HourlyPattern = s.getHourlyPattern(ctx, startDate, endDate)

	// Geographic distribution
	analytics.GeoDistribution = s.getGeoDistribution(ctx, startDate, endDate)

	// Risk distribution
	analytics.RiskDistribution = s.getRiskDistribution(ctx, startDate, endDate)

	// Auth methods
	analytics.AuthMethods = s.getAuthMethodStats(ctx, startDate, endDate)

	// Top failed users
	analytics.TopFailedUsers = s.getTopFailedUsers(ctx, startDate, endDate)

	// Device types
	analytics.DeviceTypes = s.getDeviceTypeStats(ctx, startDate, endDate)

	c.JSON(http.StatusOK, gin.H{"analytics": analytics})
}

func (s *Service) getLoginSummary(ctx context.Context, start, end time.Time) LoginSummary {
	var summary LoginSummary

	// Total and successful logins
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN success THEN 1 ELSE 0 END), 0)
		 FROM login_history WHERE created_at BETWEEN $1 AND $2`,
		start, end).Scan(&summary.TotalLogins, &summary.SuccessfulLogins)

	summary.FailedLogins = summary.TotalLogins - summary.SuccessfulLogins

	// Unique users
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM login_history WHERE created_at BETWEEN $1 AND $2`,
		start, end).Scan(&summary.UniqueUsers)

	// New devices
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE created_at BETWEEN $1 AND $2`,
		start, end).Scan(&summary.NewDevices)

	// High risk logins
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history WHERE risk_score >= 70 AND created_at BETWEEN $1 AND $2`,
		start, end).Scan(&summary.HighRiskLogins)

	// Average risk score
	s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(risk_score), 0) FROM login_history WHERE created_at BETWEEN $1 AND $2`,
		start, end).Scan(&summary.AverageRiskScore)

	// MFA challenges (approximation from audit events)
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'mfa_verified' AND timestamp BETWEEN $1 AND $2`,
		start, end).Scan(&summary.MFAChallenges)

	return summary
}

func (s *Service) getDailyLoginTrends(ctx context.Context, start, end time.Time) []DailyLoginStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT DATE(created_at) as date,
		        COALESCE(SUM(CASE WHEN success THEN 1 ELSE 0 END), 0) as successful,
		        COALESCE(SUM(CASE WHEN NOT success THEN 1 ELSE 0 END), 0) as failed,
		        COALESCE(SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END), 0) as high_risk
		 FROM login_history
		 WHERE created_at BETWEEN $1 AND $2
		 GROUP BY DATE(created_at)
		 ORDER BY date`,
		start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var trends []DailyLoginStats
	for rows.Next() {
		var stat DailyLoginStats
		var date time.Time
		if err := rows.Scan(&date, &stat.Successful, &stat.Failed, &stat.HighRisk); err == nil {
			stat.Date = date.Format("2006-01-02")
			trends = append(trends, stat)
		}
	}
	return trends
}

func (s *Service) getHourlyPattern(ctx context.Context, start, end time.Time) []HourlyStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT EXTRACT(HOUR FROM created_at)::int as hour,
		        COALESCE(SUM(CASE WHEN success THEN 1 ELSE 0 END), 0) as successful,
		        COALESCE(SUM(CASE WHEN NOT success THEN 1 ELSE 0 END), 0) as failed
		 FROM login_history
		 WHERE created_at BETWEEN $1 AND $2
		 GROUP BY hour
		 ORDER BY hour`,
		start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	// Initialize all hours
	hourMap := make(map[int]*HourlyStats)
	for i := 0; i < 24; i++ {
		hourMap[i] = &HourlyStats{Hour: i}
	}

	for rows.Next() {
		var hour, successful, failed int
		if err := rows.Scan(&hour, &successful, &failed); err == nil {
			if stat, ok := hourMap[hour]; ok {
				stat.Successful = successful
				stat.Failed = failed
			}
		}
	}

	var stats []HourlyStats
	for i := 0; i < 24; i++ {
		stats = append(stats, *hourMap[i])
	}
	return stats
}

func (s *Service) getGeoDistribution(ctx context.Context, start, end time.Time) []GeoLoginStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT COALESCE(location, 'Unknown') as location,
		        COUNT(*) as count,
		        COALESCE(SUM(CASE WHEN NOT success THEN 1 ELSE 0 END), 0) as failed,
		        COALESCE(AVG(risk_score), 0) as avg_risk
		 FROM login_history
		 WHERE created_at BETWEEN $1 AND $2
		 GROUP BY location
		 ORDER BY count DESC
		 LIMIT 10`,
		start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []GeoLoginStats
	for rows.Next() {
		var stat GeoLoginStats
		var location string
		if err := rows.Scan(&location, &stat.Count, &stat.Failed, &stat.AvgRisk); err == nil {
			// Parse "City, Country" format
			stat.City = location
			stat.Country = location
			stats = append(stats, stat)
		}
	}
	return stats
}

func (s *Service) getRiskDistribution(ctx context.Context, start, end time.Time) []RiskBucketStats {
	buckets := []struct {
		name string
		min  int
		max  int
	}{
		{"Low (0-29)", 0, 29},
		{"Medium (30-49)", 30, 49},
		{"High (50-69)", 50, 69},
		{"Critical (70-100)", 70, 100},
	}

	var stats []RiskBucketStats
	for _, b := range buckets {
		var count int
		s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM login_history
			 WHERE risk_score >= $1 AND risk_score <= $2 AND created_at BETWEEN $3 AND $4`,
			b.min, b.max, start, end).Scan(&count)

		stats = append(stats, RiskBucketStats{
			Bucket: b.name,
			Min:    b.min,
			Max:    b.max,
			Count:  count,
		})
	}
	return stats
}

func (s *Service) getAuthMethodStats(ctx context.Context, start, end time.Time) []AuthMethodStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT UNNEST(auth_methods) as method, COUNT(*) as count
		 FROM login_history
		 WHERE created_at BETWEEN $1 AND $2 AND auth_methods IS NOT NULL
		 GROUP BY method
		 ORDER BY count DESC`,
		start, end)
	if err != nil {
		return []AuthMethodStats{
			{Method: "password", Count: 0},
		}
	}
	defer rows.Close()

	var stats []AuthMethodStats
	for rows.Next() {
		var stat AuthMethodStats
		if err := rows.Scan(&stat.Method, &stat.Count); err == nil {
			stats = append(stats, stat)
		}
	}

	if len(stats) == 0 {
		stats = append(stats, AuthMethodStats{Method: "password", Count: 0})
	}
	return stats
}

func (s *Service) getTopFailedUsers(ctx context.Context, start, end time.Time) []FailedUserStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT lh.user_id, COALESCE(u.email, lh.user_id) as email,
		        COUNT(*) as failed_count, MAX(lh.created_at) as last_attempt
		 FROM login_history lh
		 LEFT JOIN users u ON lh.user_id = u.id
		 WHERE lh.success = false AND lh.created_at BETWEEN $1 AND $2
		 GROUP BY lh.user_id, u.email
		 ORDER BY failed_count DESC
		 LIMIT 10`,
		start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []FailedUserStats
	for rows.Next() {
		var stat FailedUserStats
		var lastAttempt time.Time
		if err := rows.Scan(&stat.UserID, &stat.Email, &stat.FailedCount, &lastAttempt); err == nil {
			stat.LastAttempt = lastAttempt.Format(time.RFC3339)
			stats = append(stats, stat)
		}
	}
	return stats
}

func (s *Service) getDeviceTypeStats(ctx context.Context, start, end time.Time) []DeviceTypeStats {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT
		   CASE
		     WHEN user_agent ILIKE '%mobile%' OR user_agent ILIKE '%android%' OR user_agent ILIKE '%iphone%' THEN 'Mobile'
		     WHEN user_agent ILIKE '%tablet%' OR user_agent ILIKE '%ipad%' THEN 'Tablet'
		     ELSE 'Desktop'
		   END as device_type,
		   CASE
		     WHEN user_agent ILIKE '%chrome%' AND user_agent NOT ILIKE '%edg%' THEN 'Chrome'
		     WHEN user_agent ILIKE '%firefox%' THEN 'Firefox'
		     WHEN user_agent ILIKE '%safari%' AND user_agent NOT ILIKE '%chrome%' THEN 'Safari'
		     WHEN user_agent ILIKE '%edg%' THEN 'Edge'
		     ELSE 'Other'
		   END as browser,
		   COUNT(*) as count
		 FROM login_history
		 WHERE created_at BETWEEN $1 AND $2
		 GROUP BY device_type, browser
		 ORDER BY count DESC`,
		start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []DeviceTypeStats
	for rows.Next() {
		var stat DeviceTypeStats
		if err := rows.Scan(&stat.DeviceType, &stat.Browser, &stat.Count); err == nil {
			stats = append(stats, stat)
		}
	}
	return stats
}
