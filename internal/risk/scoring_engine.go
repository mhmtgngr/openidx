package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// UserRiskProfile holds a user's learned baseline behavior
type UserRiskProfile struct {
	UserID            string    `json:"user_id"`
	TypicalLoginHours []int     `json:"typical_login_hours"`
	TypicalCountries  []string  `json:"typical_countries"`
	TypicalIPs        []string  `json:"typical_ips"`
	AvgRiskScore      float64   `json:"avg_risk_score"`
	LoginCount        int       `json:"login_count"`
	LastUpdatedAt     time.Time `json:"last_updated_at"`
}

// RiskScoreBreakdown provides a detailed breakdown of a risk score calculation
type RiskScoreBreakdown struct {
	TotalScore     int            `json:"total_score"`
	Factors        map[string]int `json:"factors"`
	Anomalies      []string       `json:"anomalies"`
	Recommendation string         `json:"recommendation"`
}

// LoginPatterns aggregates login behavior patterns for a user
type LoginPatterns struct {
	HourlyDistribution  map[int]int    `json:"hourly_distribution"`
	DailyDistribution   map[string]int `json:"daily_distribution"`
	CountryDistribution map[string]int `json:"country_distribution"`
	DeviceTypes         map[string]int `json:"device_types"`
	AvgSessionDuration  float64        `json:"avg_session_duration_minutes"`
}

// GetUserRiskProfile loads a user's risk baseline from user_risk_baselines table.
// Returns a default profile if none is found.
func (s *Service) GetUserRiskProfile(ctx context.Context, userID string) (*UserRiskProfile, error) {
	profile := &UserRiskProfile{
		UserID: userID,
	}

	var hoursJSON, countriesJSON, ipsJSON []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT typical_login_hours, typical_countries, typical_ips,
		       avg_risk_score, login_count, last_updated_at
		FROM user_risk_baselines
		WHERE user_id = $1
	`, userID).Scan(&hoursJSON, &countriesJSON, &ipsJSON,
		&profile.AvgRiskScore, &profile.LoginCount, &profile.LastUpdatedAt)

	if err != nil {
		// Return a default profile when no baseline exists
		s.logger.Debug("No risk baseline found for user, returning defaults",
			zap.String("user_id", userID))
		profile.TypicalLoginHours = []int{}
		profile.TypicalCountries = []string{}
		profile.TypicalIPs = []string{}
		profile.AvgRiskScore = 0
		profile.LoginCount = 0
		profile.LastUpdatedAt = time.Time{}
		return profile, nil
	}

	if len(hoursJSON) > 0 {
		if err := json.Unmarshal(hoursJSON, &profile.TypicalLoginHours); err != nil {
			s.logger.Warn("corrupted risk profile data: TypicalLoginHours", zap.Error(err))
		}
	}
	if len(countriesJSON) > 0 {
		if err := json.Unmarshal(countriesJSON, &profile.TypicalCountries); err != nil {
			s.logger.Warn("corrupted risk profile data: TypicalCountries", zap.Error(err))
		}
	}
	if len(ipsJSON) > 0 {
		if err := json.Unmarshal(ipsJSON, &profile.TypicalIPs); err != nil {
			s.logger.Warn("corrupted risk profile data: TypicalIPs", zap.Error(err))
		}
	}

	return profile, nil
}

// UpdateUserRiskBaseline calculates and upserts a user's behavioral baseline
// from the last 30 days of audit_events.
func (s *Service) UpdateUserRiskBaseline(ctx context.Context, userID string) error {
	s.logger.Info("Updating risk baseline for user", zap.String("user_id", userID))

	// Gather typical login hours from last 30 days
	hourCounts := make(map[int]int)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS cnt
		FROM audit_events
		WHERE actor_id = $1
		  AND event_type = 'authentication'
		  AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY hour
		ORDER BY cnt DESC
	`, userID)
	if err != nil {
		return fmt.Errorf("failed to query login hours: %w", err)
	}
	for rows.Next() {
		var hour, cnt int
		if rows.Scan(&hour, &cnt) == nil {
			hourCounts[hour] = cnt
		}
	}
	rows.Close()

	// Identify typical hours (top hours covering 80% of logins)
	totalLogins := 0
	for _, cnt := range hourCounts {
		totalLogins += cnt
	}
	var typicalHours []int
	threshold := int(float64(totalLogins) * 0.8)
	accumulated := 0
	// Sort by count descending by iterating
	for accumulated < threshold && len(typicalHours) < 24 {
		bestHour := -1
		bestCnt := 0
		for h, cnt := range hourCounts {
			if cnt > bestCnt {
				alreadyAdded := false
				for _, th := range typicalHours {
					if th == h {
						alreadyAdded = true
						break
					}
				}
				if !alreadyAdded {
					bestHour = h
					bestCnt = cnt
				}
			}
		}
		if bestHour == -1 {
			break
		}
		typicalHours = append(typicalHours, bestHour)
		accumulated += bestCnt
	}

	// Gather typical countries from login_history
	var typicalCountries []string
	countryRows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT location
		FROM login_history
		WHERE user_id = $1
		  AND success = true
		  AND created_at > NOW() - INTERVAL '30 days'
		  AND location IS NOT NULL AND location != ''
		ORDER BY location
		LIMIT 10
	`, userID)
	if err == nil {
		for countryRows.Next() {
			var loc string
			if countryRows.Scan(&loc) == nil && loc != "" {
				country := extractCountry(loc)
				// Deduplicate
				found := false
				for _, c := range typicalCountries {
					if c == country {
						found = true
						break
					}
				}
				if !found {
					typicalCountries = append(typicalCountries, country)
				}
			}
		}
		countryRows.Close()
	}

	// Gather typical IPs from login_history
	var typicalIPs []string
	ipRows, err := s.db.Pool.Query(ctx, `
		SELECT ip_address, COUNT(*) AS cnt
		FROM login_history
		WHERE user_id = $1
		  AND success = true
		  AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY ip_address
		ORDER BY cnt DESC
		LIMIT 20
	`, userID)
	if err == nil {
		for ipRows.Next() {
			var ip string
			var cnt int
			if ipRows.Scan(&ip, &cnt) == nil && ip != "" {
				typicalIPs = append(typicalIPs, ip)
			}
		}
		ipRows.Close()
	}

	// Calculate average risk score
	var avgRisk float64
	var loginCount int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(risk_score), 0), COUNT(*)
		FROM login_history
		WHERE user_id = $1
		  AND success = true
		  AND created_at > NOW() - INTERVAL '30 days'
	`, userID).Scan(&avgRisk, &loginCount)
	if err != nil {
		return fmt.Errorf("failed to query avg risk score: %w", err)
	}

	// Marshal arrays to JSON for storage
	hoursJSON, _ := json.Marshal(typicalHours)
	countriesJSON, _ := json.Marshal(typicalCountries)
	ipsJSON, _ := json.Marshal(typicalIPs)

	// Upsert into user_risk_baselines
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO user_risk_baselines (user_id, typical_login_hours, typical_countries, typical_ips, avg_risk_score, login_count, last_updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			typical_login_hours = EXCLUDED.typical_login_hours,
			typical_countries = EXCLUDED.typical_countries,
			typical_ips = EXCLUDED.typical_ips,
			avg_risk_score = EXCLUDED.avg_risk_score,
			login_count = EXCLUDED.login_count,
			last_updated_at = NOW()
	`, userID, hoursJSON, countriesJSON, ipsJSON, avgRisk, loginCount)
	if err != nil {
		return fmt.Errorf("failed to upsert risk baseline: %w", err)
	}

	s.logger.Info("Risk baseline updated",
		zap.String("user_id", userID),
		zap.Int("login_count", loginCount),
		zap.Float64("avg_risk", avgRisk),
		zap.Int("typical_hours", len(typicalHours)),
		zap.Int("typical_countries", len(typicalCountries)),
		zap.Int("typical_ips", len(typicalIPs)),
	)

	return nil
}

// CalculateEnhancedRiskScore computes a detailed risk score by comparing the
// current login context against the user's learned behavioral baseline.
func (s *Service) CalculateEnhancedRiskScore(ctx context.Context, userID, ip, country, userAgent string, loginHour int) (*RiskScoreBreakdown, error) {
	breakdown := &RiskScoreBreakdown{
		Factors:   make(map[string]int),
		Anomalies: []string{},
	}

	// Load baseline
	profile, err := s.GetUserRiskProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load risk profile: %w", err)
	}

	// Factor 1: Unusual login hour (+15)
	isUnusualHour, _ := s.DetectAnomalousLoginTime(ctx, userID, loginHour)
	if isUnusualHour {
		breakdown.Factors["unusual_hour"] = 15
		breakdown.Anomalies = append(breakdown.Anomalies,
			fmt.Sprintf("Login at hour %d is outside typical pattern", loginHour))
	}

	// Factor 2: Unusual country (+25)
	if country != "" && profile.LoginCount > 0 {
		knownCountry := false
		for _, c := range profile.TypicalCountries {
			if c == country {
				knownCountry = true
				break
			}
		}
		if !knownCountry {
			breakdown.Factors["unusual_country"] = 25
			breakdown.Anomalies = append(breakdown.Anomalies,
				fmt.Sprintf("Login from country '%s' not seen in baseline", country))
		}
	}

	// Factor 3: Unusual IP (+10)
	if ip != "" && profile.LoginCount > 0 {
		knownIP := false
		for _, knownAddr := range profile.TypicalIPs {
			if knownAddr == ip {
				knownIP = true
				break
			}
		}
		if !knownIP {
			breakdown.Factors["unusual_ip"] = 10
			breakdown.Anomalies = append(breakdown.Anomalies,
				fmt.Sprintf("Login from IP '%s' not seen in baseline", ip))
		}
	}

	// Factor 4: New device / user-agent (+10)
	if userAgent != "" {
		fingerprint := s.ComputeDeviceFingerprint(ip, userAgent)
		var deviceCount int
		s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
			userID, fingerprint).Scan(&deviceCount)
		if deviceCount == 0 {
			breakdown.Factors["new_device"] = 10
			breakdown.Anomalies = append(breakdown.Anomalies, "Login from unrecognized device")
		}
	}

	// Factor 5: No MFA configured (+20)
	var mfaCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_totp WHERE user_id = $1 AND enabled = true`, userID).Scan(&mfaCount)
	var webauthnCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1`, userID).Scan(&webauthnCount)
	if mfaCount == 0 && webauthnCount == 0 {
		breakdown.Factors["no_mfa"] = 20
		breakdown.Anomalies = append(breakdown.Anomalies, "No MFA method configured for this user")
	}

	// Factor 6: Credential stuffing detected (+30)
	isStuffing, _ := s.DetectCredentialStuffing(ctx, ip, 10*time.Minute)
	if isStuffing {
		breakdown.Factors["credential_stuffing"] = 30
		breakdown.Anomalies = append(breakdown.Anomalies,
			fmt.Sprintf("Credential stuffing detected from IP '%s'", ip))
	}

	// Sum up total score
	total := 0
	for _, v := range breakdown.Factors {
		total += v
	}
	if total > 100 {
		total = 100
	}
	breakdown.TotalScore = total

	// Generate recommendation
	switch {
	case total >= 70:
		breakdown.Recommendation = "block"
	case total >= 40:
		breakdown.Recommendation = "step_up_mfa"
	case total >= 20:
		breakdown.Recommendation = "monitor"
	default:
		breakdown.Recommendation = "allow"
	}

	s.logger.Debug("Enhanced risk score calculated",
		zap.String("user_id", userID),
		zap.Int("total_score", breakdown.TotalScore),
		zap.String("recommendation", breakdown.Recommendation),
		zap.Int("anomaly_count", len(breakdown.Anomalies)),
	)

	return breakdown, nil
}

// DetectAnomalousLoginTime checks if the given login hour is outside
// the user's typical login hours from their baseline profile.
func (s *Service) DetectAnomalousLoginTime(ctx context.Context, userID string, loginHour int) (bool, error) {
	profile, err := s.GetUserRiskProfile(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to load risk profile: %w", err)
	}

	// If no baseline exists yet, we cannot determine anomaly
	if profile.LoginCount == 0 || len(profile.TypicalLoginHours) == 0 {
		return false, nil
	}

	for _, h := range profile.TypicalLoginHours {
		if h == loginHour {
			return false, nil
		}
	}

	s.logger.Debug("Anomalous login time detected",
		zap.String("user_id", userID),
		zap.Int("login_hour", loginHour),
		zap.Ints("typical_hours", profile.TypicalLoginHours),
	)

	return true, nil
}

// DetectCredentialStuffing checks if there are more than 10 distinct usernames
// attempting login from the same IP address within the given time window.
func (s *Service) DetectCredentialStuffing(ctx context.Context, ip string, window time.Duration) (bool, error) {
	var distinctUsers int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT actor_id)
		FROM audit_events
		WHERE actor_ip = $1
		  AND event_type = 'authentication'
		  AND outcome = 'failure'
		  AND timestamp > NOW() - $2::interval
	`, ip, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&distinctUsers)
	if err != nil {
		return false, fmt.Errorf("failed to check credential stuffing: %w", err)
	}

	if distinctUsers > 10 {
		s.logger.Warn("Credential stuffing detected",
			zap.String("ip", ip),
			zap.Int("distinct_users", distinctUsers),
			zap.Duration("window", window),
		)
		return true, nil
	}

	return false, nil
}

// GetUserLoginPatterns queries audit_events for login events and aggregates
// the results into behavioral patterns for a user.
func (s *Service) GetUserLoginPatterns(ctx context.Context, userID string) (*LoginPatterns, error) {
	patterns := &LoginPatterns{
		HourlyDistribution:  make(map[int]int),
		DailyDistribution:   make(map[string]int),
		CountryDistribution: make(map[string]int),
		DeviceTypes:         make(map[string]int),
	}

	// Hourly distribution
	hourRows, err := s.db.Pool.Query(ctx, `
		SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS cnt
		FROM audit_events
		WHERE actor_id = $1
		  AND event_type = 'authentication'
		  AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '90 days'
		GROUP BY hour
		ORDER BY hour
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query hourly distribution: %w", err)
	}
	for hourRows.Next() {
		var hour, cnt int
		if hourRows.Scan(&hour, &cnt) == nil {
			patterns.HourlyDistribution[hour] = cnt
		}
	}
	hourRows.Close()

	// Daily distribution (day of week)
	dayRows, err := s.db.Pool.Query(ctx, `
		SELECT TO_CHAR(timestamp, 'Day') AS day_name, COUNT(*) AS cnt
		FROM audit_events
		WHERE actor_id = $1
		  AND event_type = 'authentication'
		  AND outcome = 'success'
		  AND timestamp > NOW() - INTERVAL '90 days'
		GROUP BY day_name
		ORDER BY cnt DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily distribution: %w", err)
	}
	for dayRows.Next() {
		var dayName string
		var cnt int
		if dayRows.Scan(&dayName, &cnt) == nil {
			patterns.DailyDistribution[dayName] = cnt
		}
	}
	dayRows.Close()

	// Country distribution from login_history
	countryRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(location, 'Unknown') AS loc, COUNT(*) AS cnt
		FROM login_history
		WHERE user_id = $1
		  AND success = true
		  AND created_at > NOW() - INTERVAL '90 days'
		GROUP BY loc
		ORDER BY cnt DESC
		LIMIT 20
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query country distribution: %w", err)
	}
	for countryRows.Next() {
		var loc string
		var cnt int
		if countryRows.Scan(&loc, &cnt) == nil {
			country := extractCountry(loc)
			patterns.CountryDistribution[country] += cnt
		}
	}
	countryRows.Close()

	// Device types from known_devices
	deviceRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(name, 'Unknown') AS device_name, COUNT(*) AS cnt
		FROM known_devices
		WHERE user_id = $1
		GROUP BY device_name
		ORDER BY cnt DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query device types: %w", err)
	}
	for deviceRows.Next() {
		var name string
		var cnt int
		if deviceRows.Scan(&name, &cnt) == nil {
			patterns.DeviceTypes[name] = cnt
		}
	}
	deviceRows.Close()

	// Average session duration in minutes
	var avgDuration *float64
	s.db.Pool.QueryRow(ctx, `
		SELECT AVG(EXTRACT(EPOCH FROM (expires_at - created_at)) / 60.0)
		FROM sessions
		WHERE user_id = $1
		  AND created_at > NOW() - INTERVAL '90 days'
	`, userID).Scan(&avgDuration)
	if avgDuration != nil {
		patterns.AvgSessionDuration = *avgDuration
	}

	return patterns, nil
}

// GetRiskTimeline returns daily average risk scores for the last N days,
// suitable for charting risk trends over time.
func (s *Service) GetRiskTimeline(ctx context.Context, days int) ([]map[string]interface{}, error) {
	if days <= 0 {
		days = 30
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(created_at) AS day,
		       AVG(risk_score) AS avg_score,
		       MAX(risk_score) AS max_score,
		       COUNT(*) AS login_count
		FROM login_history
		WHERE created_at > NOW() - ($1::int || ' days')::interval
		GROUP BY day
		ORDER BY day
	`, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query risk timeline: %w", err)
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var avgScore float64
		var maxScore, loginCount int
		if err := rows.Scan(&day, &avgScore, &maxScore, &loginCount); err != nil {
			s.logger.Warn("Failed to scan risk timeline row", zap.Error(err))
			continue
		}
		timeline = append(timeline, map[string]interface{}{
			"date":        day.Format("2006-01-02"),
			"avg_score":   int(avgScore),
			"max_score":   maxScore,
			"login_count": loginCount,
		})
	}

	if timeline == nil {
		timeline = []map[string]interface{}{}
	}

	return timeline, nil
}
