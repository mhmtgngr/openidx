package admin

import (
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PredictionSummary holds all prediction results
type PredictionSummary struct {
	LoginForecast    *LoginForecast    `json:"login_forecast"`
	RiskForecast     *RiskForecast     `json:"risk_forecast"`
	CapacityForecast *CapacityForecast `json:"capacity_forecast"`
	AccountGrowth    *AccountGrowth    `json:"account_growth"`
	ChurnRisk        []ChurnRiskUser   `json:"churn_risk_users"`
}

// LoginForecast predicts login volume
type LoginForecast struct {
	Historical []DailyMetric `json:"historical"`
	Predicted  []DailyMetric `json:"predicted"`
	Trend      string        `json:"trend"`
	AvgDaily   float64       `json:"avg_daily"`
}

// RiskForecast predicts risk score trends
type RiskForecast struct {
	Historical []DailyFloat `json:"historical"`
	Predicted  []DailyFloat `json:"predicted"`
	Trend      string       `json:"trend"`
	CurrentAvg float64      `json:"current_avg"`
}

// CapacityForecast estimates infrastructure needs
type CapacityForecast struct {
	PeakConcurrentSessions int     `json:"peak_concurrent_sessions"`
	AvgConcurrentSessions  int     `json:"avg_concurrent_sessions"`
	PeakHour              int     `json:"peak_hour"`
	PeakDayOfWeek         string  `json:"peak_day_of_week"`
	SessionGrowthRate     float64 `json:"session_growth_rate_pct"`
	RecommendedCapacity   int     `json:"recommended_capacity"`
	LicenseUtilization    float64 `json:"license_utilization_pct"`
}

// AccountGrowth projects user count growth
type AccountGrowth struct {
	CurrentUsers    int           `json:"current_users"`
	GrowthRate      float64       `json:"growth_rate_monthly_pct"`
	Projected30d    int           `json:"projected_30d"`
	Projected90d    int           `json:"projected_90d"`
	Historical      []DailyMetric `json:"historical"`
}

// ChurnRiskUser is a user at risk of departing
type ChurnRiskUser struct {
	UserID          string  `json:"user_id"`
	Username        string  `json:"username"`
	LastLogin       string  `json:"last_login"`
	LoginFreqChange float64 `json:"login_freq_change_pct"`
	RiskScore       float64 `json:"risk_score"`
}

// DailyMetric is a date-value pair for integers
type DailyMetric struct {
	Date  string `json:"date"`
	Value int    `json:"value"`
}

// DailyFloat is a date-value pair for floats
type DailyFloat struct {
	Date  string  `json:"date"`
	Value float64 `json:"value"`
}

// --- Handlers ---

func (s *Service) handlePredictionsSummary(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	summary := PredictionSummary{}

	// Login forecast
	loginHist := []DailyMetric{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as d, COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY d ORDER BY d`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d time.Time
			var cnt int
			rows.Scan(&d, &cnt)
			loginHist = append(loginHist, DailyMetric{Date: d.Format("2006-01-02"), Value: cnt})
		}
	}
	predicted := forecastSimpleMA(loginHist, 7)
	trend := detectTrend(loginHist)
	avgDaily := avgMetric(loginHist)
	summary.LoginForecast = &LoginForecast{Historical: loginHist, Predicted: predicted, Trend: trend, AvgDaily: avgDaily}

	// Risk forecast
	riskHist := []DailyFloat{}
	rRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as d, AVG(COALESCE((details->>'risk_score')::float, 0)) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY d ORDER BY d`)
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var d time.Time
			var avg float64
			rRows.Scan(&d, &avg)
			riskHist = append(riskHist, DailyFloat{Date: d.Format("2006-01-02"), Value: math.Round(avg*100) / 100})
		}
	}
	riskPredicted := forecastFloatMA(riskHist, 7)
	riskTrend := detectFloatTrend(riskHist)
	currentRiskAvg := avgFloat(riskHist)
	summary.RiskForecast = &RiskForecast{Historical: riskHist, Predicted: riskPredicted, Trend: riskTrend, CurrentAvg: currentRiskAvg}

	// Capacity forecast
	var peakSessions, avgSessions int
	s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(cnt), 0), COALESCE(AVG(cnt)::int, 0) FROM (
			SELECT DATE_TRUNC('hour', created_at) as h, COUNT(*) as cnt FROM user_sessions
			WHERE created_at > NOW() - INTERVAL '7 days' GROUP BY h
		) sub`).Scan(&peakSessions, &avgSessions)

	var peakHour int
	s.db.Pool.QueryRow(ctx, `
		SELECT EXTRACT(HOUR FROM created_at)::int as h FROM user_sessions
		WHERE created_at > NOW() - INTERVAL '7 days'
		GROUP BY h ORDER BY COUNT(*) DESC LIMIT 1`).Scan(&peakHour)

	var peakDow int
	s.db.Pool.QueryRow(ctx, `
		SELECT EXTRACT(DOW FROM created_at)::int as dow FROM user_sessions
		WHERE created_at > NOW() - INTERVAL '30 days'
		GROUP BY dow ORDER BY COUNT(*) DESC LIMIT 1`).Scan(&peakDow)
	dowNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	peakDayName := "Monday"
	if peakDow >= 0 && peakDow < 7 {
		peakDayName = dowNames[peakDow]
	}

	var totalUsers, activeUsers int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = true").Scan(&activeUsers)

	licenseUtil := 0.0
	if totalUsers > 0 {
		licenseUtil = float64(activeUsers) / float64(totalUsers) * 100
	}

	summary.CapacityForecast = &CapacityForecast{
		PeakConcurrentSessions: peakSessions,
		AvgConcurrentSessions:  avgSessions,
		PeakHour:               peakHour,
		PeakDayOfWeek:          peakDayName,
		SessionGrowthRate:      0, // Would calculate from multi-week data
		RecommendedCapacity:    int(float64(peakSessions) * 1.5),
		LicenseUtilization:     math.Round(licenseUtil*10) / 10,
	}

	// Account growth
	growthHist := []DailyMetric{}
	gRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(created_at) as d, COUNT(*) FROM users
		WHERE created_at > NOW() - INTERVAL '90 days'
		GROUP BY d ORDER BY d`)
	if err == nil {
		defer gRows.Close()
		for gRows.Next() {
			var d time.Time
			var cnt int
			gRows.Scan(&d, &cnt)
			growthHist = append(growthHist, DailyMetric{Date: d.Format("2006-01-02"), Value: cnt})
		}
	}
	totalNew30d := sumLastN(growthHist, 30)
	monthlyRate := 0.0
	if activeUsers > 0 {
		monthlyRate = float64(totalNew30d) / float64(activeUsers) * 100
	}
	summary.AccountGrowth = &AccountGrowth{
		CurrentUsers:   activeUsers,
		GrowthRate:     math.Round(monthlyRate*10) / 10,
		Projected30d:   activeUsers + totalNew30d,
		Projected90d:   activeUsers + totalNew30d*3,
		Historical:     growthHist,
	}

	// Churn risk - users with declining login frequency
	churnUsers := []ChurnRiskUser{}
	cRows, err := s.db.Pool.Query(ctx, `
		WITH recent AS (
			SELECT actor_id, COUNT(*) as cnt FROM audit_events
			WHERE event_type = 'authentication' AND outcome = 'success'
			AND timestamp > NOW() - INTERVAL '15 days'
			GROUP BY actor_id
		), previous AS (
			SELECT actor_id, COUNT(*) as cnt FROM audit_events
			WHERE event_type = 'authentication' AND outcome = 'success'
			AND timestamp BETWEEN NOW() - INTERVAL '30 days' AND NOW() - INTERVAL '15 days'
			GROUP BY actor_id
		)
		SELECT p.actor_id, u.username, u.last_login,
			COALESCE(r.cnt, 0) as recent_cnt, p.cnt as prev_cnt
		FROM previous p
		LEFT JOIN recent r ON p.actor_id = r.actor_id
		JOIN users u ON p.actor_id = u.id::text
		WHERE COALESCE(r.cnt, 0) < p.cnt * 0.5 AND p.cnt >= 3
		ORDER BY (COALESCE(r.cnt::float, 0) / p.cnt::float) ASC
		LIMIT 10`)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var uid, uname string
			var lastLogin *time.Time
			var recentCnt, prevCnt int
			cRows.Scan(&uid, &uname, &lastLogin, &recentCnt, &prevCnt)
			change := -100.0
			if prevCnt > 0 {
				change = (float64(recentCnt-prevCnt) / float64(prevCnt)) * 100
			}
			ll := "never"
			if lastLogin != nil {
				ll = lastLogin.Format("2006-01-02")
			}
			score := math.Abs(change) / 100 * 0.7
			if recentCnt == 0 {
				score = 0.9
			}
			churnUsers = append(churnUsers, ChurnRiskUser{
				UserID: uid, Username: uname, LastLogin: ll,
				LoginFreqChange: math.Round(change*10) / 10,
				RiskScore:       math.Round(score*100) / 100,
			})
		}
	}
	summary.ChurnRisk = churnUsers

	c.JSON(http.StatusOK, summary)
}

func (s *Service) handleLoginForecast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	hist := []DailyMetric{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as d, COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '60 days'
		GROUP BY d ORDER BY d`)
	if err != nil {
		s.logger.Error("failed to query login history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get login data"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var d time.Time
		var cnt int
		rows.Scan(&d, &cnt)
		hist = append(hist, DailyMetric{Date: d.Format("2006-01-02"), Value: cnt})
	}

	predicted := forecastSimpleMA(hist, 14)
	c.JSON(http.StatusOK, gin.H{
		"historical": hist,
		"predicted":  predicted,
		"trend":      detectTrend(hist),
		"avg_daily":  avgMetric(hist),
	})
}

func (s *Service) handleRiskForecast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	hist := []DailyFloat{}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as d, AVG(COALESCE((details->>'risk_score')::float, 0)) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '60 days'
		GROUP BY d ORDER BY d`)
	if err != nil {
		s.logger.Error("failed to query risk history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get risk data"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var d time.Time
		var avg float64
		rows.Scan(&d, &avg)
		hist = append(hist, DailyFloat{Date: d.Format("2006-01-02"), Value: math.Round(avg*100) / 100})
	}

	predicted := forecastFloatMA(hist, 14)
	c.JSON(http.StatusOK, gin.H{
		"historical":  hist,
		"predicted":   predicted,
		"trend":       detectFloatTrend(hist),
		"current_avg": avgFloat(hist),
	})
}

func (s *Service) handleCapacityForecast(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	// Hourly session distribution
	hourly := []map[string]interface{}{}
	hRows, err := s.db.Pool.Query(ctx, `
		SELECT EXTRACT(HOUR FROM created_at)::int as h, COUNT(*) FROM user_sessions
		WHERE created_at > NOW() - INTERVAL '7 days'
		GROUP BY h ORDER BY h`)
	if err == nil {
		defer hRows.Close()
		for hRows.Next() {
			var h, cnt int
			hRows.Scan(&h, &cnt)
			hourly = append(hourly, map[string]interface{}{"hour": h, "sessions": cnt})
		}
	}

	// Weekly trend
	weekly := []map[string]interface{}{}
	wRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE_TRUNC('week', created_at)::date as w, COUNT(*) FROM user_sessions
		WHERE created_at > NOW() - INTERVAL '12 weeks'
		GROUP BY w ORDER BY w`)
	if err == nil {
		defer wRows.Close()
		for wRows.Next() {
			var w time.Time
			var cnt int
			wRows.Scan(&w, &cnt)
			weekly = append(weekly, map[string]interface{}{"week": w.Format("2006-01-02"), "sessions": cnt})
		}
	}

	var totalUsers, activeSessions int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = true").Scan(&totalUsers)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW()").Scan(&activeSessions)

	c.JSON(http.StatusOK, gin.H{
		"hourly_distribution": hourly,
		"weekly_trend":        weekly,
		"total_users":         totalUsers,
		"active_sessions":     activeSessions,
		"utilization_pct":     safeDiv(float64(activeSessions), float64(totalUsers)) * 100,
	})
}

// --- Statistical helpers ---

func forecastSimpleMA(hist []DailyMetric, forecastDays int) []DailyMetric {
	if len(hist) < 3 {
		return nil
	}
	window := 7
	if len(hist) < window {
		window = len(hist)
	}

	// Calculate moving average from recent data
	sum := 0
	for i := len(hist) - window; i < len(hist); i++ {
		sum += hist[i].Value
	}
	avg := float64(sum) / float64(window)

	// Detect simple trend (slope)
	slope := 0.0
	if len(hist) >= 14 {
		firstHalf := 0
		secondHalf := 0
		mid := len(hist) / 2
		for i := 0; i < mid; i++ {
			firstHalf += hist[i].Value
		}
		for i := mid; i < len(hist); i++ {
			secondHalf += hist[i].Value
		}
		firstAvg := float64(firstHalf) / float64(mid)
		secondAvg := float64(secondHalf) / float64(len(hist)-mid)
		slope = (secondAvg - firstAvg) / float64(mid)
	}

	// Generate predictions
	lastDate, _ := time.Parse("2006-01-02", hist[len(hist)-1].Date)
	predicted := []DailyMetric{}
	for i := 1; i <= forecastDays; i++ {
		d := lastDate.AddDate(0, 0, i)
		val := int(avg + slope*float64(i))
		if val < 0 {
			val = 0
		}
		predicted = append(predicted, DailyMetric{Date: d.Format("2006-01-02"), Value: val})
	}
	return predicted
}

func forecastFloatMA(hist []DailyFloat, forecastDays int) []DailyFloat {
	if len(hist) < 3 {
		return nil
	}
	window := 7
	if len(hist) < window {
		window = len(hist)
	}
	sum := 0.0
	for i := len(hist) - window; i < len(hist); i++ {
		sum += hist[i].Value
	}
	avg := sum / float64(window)

	lastDate, _ := time.Parse("2006-01-02", hist[len(hist)-1].Date)
	predicted := []DailyFloat{}
	for i := 1; i <= forecastDays; i++ {
		d := lastDate.AddDate(0, 0, i)
		predicted = append(predicted, DailyFloat{Date: d.Format("2006-01-02"), Value: math.Round(avg*100) / 100})
	}
	return predicted
}

func detectTrend(hist []DailyMetric) string {
	if len(hist) < 7 {
		return "insufficient_data"
	}
	recent := avgLastN(hist, 7)
	earlier := avgFirstN(hist, 7)
	if recent > earlier*1.1 {
		return "increasing"
	} else if recent < earlier*0.9 {
		return "decreasing"
	}
	return "stable"
}

func detectFloatTrend(hist []DailyFloat) string {
	if len(hist) < 7 {
		return "insufficient_data"
	}
	recentSum := 0.0
	earlierSum := 0.0
	cnt := min(7, len(hist)/2)
	for i := len(hist) - cnt; i < len(hist); i++ {
		recentSum += hist[i].Value
	}
	for i := 0; i < cnt; i++ {
		earlierSum += hist[i].Value
	}
	recentAvg := recentSum / float64(cnt)
	earlierAvg := earlierSum / float64(cnt)
	if recentAvg > earlierAvg*1.1 {
		return "increasing"
	} else if recentAvg < earlierAvg*0.9 {
		return "decreasing"
	}
	return "stable"
}

func avgMetric(hist []DailyMetric) float64 {
	if len(hist) == 0 {
		return 0
	}
	sum := 0
	for _, m := range hist {
		sum += m.Value
	}
	return math.Round(float64(sum)/float64(len(hist))*10) / 10
}

func avgFloat(hist []DailyFloat) float64 {
	if len(hist) == 0 {
		return 0
	}
	sum := 0.0
	for _, m := range hist {
		sum += m.Value
	}
	return math.Round(sum/float64(len(hist))*100) / 100
}

func avgLastN(hist []DailyMetric, n int) float64 {
	if len(hist) == 0 {
		return 0
	}
	if n > len(hist) {
		n = len(hist)
	}
	sum := 0
	for i := len(hist) - n; i < len(hist); i++ {
		sum += hist[i].Value
	}
	return float64(sum) / float64(n)
}

func avgFirstN(hist []DailyMetric, n int) float64 {
	if len(hist) == 0 {
		return 0
	}
	if n > len(hist) {
		n = len(hist)
	}
	sum := 0
	for i := 0; i < n; i++ {
		sum += hist[i].Value
	}
	return float64(sum) / float64(n)
}

func sumLastN(hist []DailyMetric, n int) int {
	if len(hist) == 0 {
		return 0
	}
	start := len(hist) - n
	if start < 0 {
		start = 0
	}
	sum := 0
	for i := start; i < len(hist); i++ {
		sum += hist[i].Value
	}
	return sum
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}
