// Package risk provides risk assessment and scoring for authentication and access events
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// RiskLevel represents the classification of risk
type RiskLevel string

const (
	RiskLevelLow       RiskLevel = "low"
	RiskLevelMedium    RiskLevel = "medium"
	RiskLevelHigh      RiskLevel = "high"
	RiskLevelCritical  RiskLevel = "critical"
)

// String returns the string representation of RiskLevel
func (r RiskLevel) String() string {
	return string(r)
}

// ScoreRequest contains all relevant data for risk scoring
type ScoreRequest struct {
	UserID            string  `json:"user_id"`
	IPAddress         string  `json:"ip_address"`
	UserAgent         string  `json:"user_agent"`
	DeviceFingerprint string  `json:"device_fingerprint"`
	Latitude          float64 `json:"latitude"`
	Longitude         float64 `json:"longitude"`
	Timestamp         time.Time `json:"timestamp"`
	SessionID         string  `json:"session_id,omitempty"`
	AuthMethod        string  `json:"auth_method,omitempty"`
	RequestedResource string  `json:"requested_resource,omitempty"`
}

// ScoreResult contains the risk assessment results
type ScoreResult struct {
	TotalScore       int                 `json:"total_score"`        // 0-100
	RiskLevel        RiskLevel           `json:"risk_level"`
	Factors          []RiskFactor        `json:"factors"`
	Details          map[string]float64  `json:"details"`
	RecommendActions []string            `json:"recommend_actions"`
	Timestamp        time.Time           `json:"timestamp"`
}

// RiskFactor represents an individual risk factor
type RiskFactor struct {
	Name        string  `json:"name"`
	Score       int     `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
}

// DeviceFingerprint contains device characteristics
type DeviceFingerprint struct {
	Fingerprint string    `json:"fingerprint"`
	UserAgent   string    `json:"user_agent"`
	IPAddress   string    `json:"ip_address"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	IsTrusted   bool      `json:"is_trusted"`
	IsKnown     bool      `json:"is_known"`
}

// LoginEvent represents a historical login for velocity and travel analysis
type LoginEvent struct {
	UserID        string    `json:"user_id"`
	IPAddress     string    `json:"ip_address"`
	Latitude      float64   `json:"latitude"`
	Longitude     float64   `json:"longitude"`
	Timestamp     time.Time `json:"timestamp"`
	Success       bool      `json:"success"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

// IPReputationData represents threat intelligence for an IP
type IPReputationData struct {
	IPAddress       string    `json:"ip_address"`
	IsTorExit       bool      `json:"is_tor_exit"`
	IsVPN           bool      `json:"is_vpn"`
	IsProxy         bool      `json:"is_proxy"`
	IsHosting       bool      `json:"is_hosting"`
	ThreatScore     int       `json:"threat_score"`
	FirstSeen       time.Time `json:"first_seen"`
	LastReported    time.Time `json:"last_reported"`
	ReportCount     int       `json:"report_count"`
}

// RiskScorer provides comprehensive risk scoring capabilities
type RiskScorer struct {
	db                *database.PostgresDB
	redis             *database.RedisClient
	logger            *zap.Logger
	httpClient        *http.Client

	// Scoring weights (configurable)
	IPReputationWeight      float64 // Weight for IP reputation score (0-1)
	DeviceScoreWeight       float64 // Weight for device score (0-1)
	GeolocationWeight       float64 // Weight for geolocation score (0-1)
	LoginVelocityWeight     float64 // Weight for login velocity (0-1)
	ImpossibleTravelWeight  float64 // Weight for impossible travel (0-1)

	// Thresholds
	LowRiskThreshold     int  // Below this: low risk
	MediumRiskThreshold  int  // Below this: medium risk
	HighRiskThreshold    int  // Below this: high risk
	// Above high_risk_threshold: critical risk

	// Maximum speed for possible travel (km/h) - default 900 km/h (aircraft speed)
	MaxTravelSpeed float64
}

// NewRiskScorer creates a new RiskScorer instance
func NewRiskScorer(db *database.PostgresDB, redis *database.RedisClient, logger *zap.Logger) *RiskScorer {
	return &RiskScorer{
		db:             db,
		redis:          redis,
		logger:         logger.With(zap.String("component", "risk_scorer")),
		httpClient:     &http.Client{Timeout: 10 * time.Second},

		// Default weights - sum should be approximately 1.0 for proper normalization
		IPReputationWeight:     0.25,
		DeviceScoreWeight:      0.20,
		GeolocationWeight:      0.15,
		LoginVelocityWeight:    0.20,
		ImpossibleTravelWeight: 0.20,

		// Default thresholds
		LowRiskThreshold:    30,
		MediumRiskThreshold: 50,
		HighRiskThreshold:   70,

		MaxTravelSpeed: 900, // km/h
	}
}

// Score calculates the comprehensive risk score for a login/event request
func (r *RiskScorer) Score(ctx context.Context, req ScoreRequest) (*ScoreResult, error) {
	startTime := time.Now()

	result := &ScoreResult{
		Factors:          []RiskFactor{},
		Details:          make(map[string]float64),
		RecommendActions: []string{},
		Timestamp:        time.Now(),
	}

	// 1. Calculate IP Reputation Score
	ipScore := r.CalculateIPReputationScore(req.IPAddress)
	result.Details["ip_reputation"] = ipScore

	// 2. Calculate Device Score
	deviceFingerprint := DeviceFingerprint{
		Fingerprint: req.DeviceFingerprint,
		UserAgent:   req.UserAgent,
		IPAddress:   req.IPAddress,
	}
	deviceScore := r.CalculateDeviceScore(ctx, deviceFingerprint, req.UserID)
	result.Details["device_score"] = deviceScore

	// 3. Calculate Geolocation Score
	geoScore := r.CalculateGeolocationScore(ctx, req.Latitude, req.Longitude, req.UserID)
	result.Details["geolocation"] = geoScore

	// 4. Calculate Login Velocity Score
	velocityScore := r.calculateLoginVelocityScoreWithContext(ctx, req.UserID, req.Timestamp)
	result.Details["login_velocity"] = velocityScore

	// 5. Check for Impossible Travel
	impossibleTravel, travelDistance, travelTime := r.detectImpossibleTravelWithDetails(ctx, req)
	travelScore := 0.0
	if impossibleTravel {
		travelScore = 100.0
		result.Factors = append(result.Factors, RiskFactor{
			Name:        "impossible_travel",
			Score:       100,
			Weight:      r.ImpossibleTravelWeight,
			Description: fmt.Sprintf("Impossible travel detected: %.0f km in %s", travelDistance, travelTime),
		})
	}
	result.Details["impossible_travel"] = travelScore

	// Calculate weighted score
	weightedScore := (ipScore * r.IPReputationWeight) +
	                 (deviceScore * r.DeviceScoreWeight) +
	                 (geoScore * r.GeolocationWeight) +
	                 (velocityScore * r.LoginVelocityWeight) +
	                 (travelScore * r.ImpossibleTravelWeight)

	// Convert to 0-100 scale
	finalScore := int(math.Round(weightedScore))
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	result.TotalScore = finalScore
	result.RiskLevel = r.classifyRiskLevel(finalScore)
	result.RecommendActions = r.getRecommendations(result.RiskLevel, result.Factors)

	// Add IP reputation factor if significant
	if ipScore > 30 {
		result.Factors = append(result.Factors, RiskFactor{
			Name:        "ip_reputation",
			Score:       int(ipScore),
			Weight:      r.IPReputationWeight,
			Description: r.getIPReputationDescription(req.IPAddress, ipScore),
		})
	}

	// Add device factor if significant
	if deviceScore > 30 {
		result.Factors = append(result.Factors, RiskFactor{
			Name:        "device",
			Score:       int(deviceScore),
			Weight:      r.DeviceScoreWeight,
			Description: r.getDeviceDescription(deviceScore),
		})
	}

	// Add geolocation factor if significant
	if geoScore > 30 {
		result.Factors = append(result.Factors, RiskFactor{
			Name:        "geolocation",
			Score:       int(geoScore),
			Weight:      r.GeolocationWeight,
			Description: r.getGeolocationDescription(geoScore),
		})
	}

	// Add login velocity factor if significant
	if velocityScore > 30 {
		result.Factors = append(result.Factors, RiskFactor{
			Name:        "login_velocity",
			Score:       int(velocityScore),
			Weight:      r.LoginVelocityWeight,
			Description: r.getVelocityDescription(velocityScore),
		})
	}

	r.logger.Debug("Risk score calculated",
		zap.String("user_id", req.UserID),
		zap.Int("score", finalScore),
		zap.String("risk_level", string(result.RiskLevel)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// CalculateIPReputationScore calculates a score based on IP threat intelligence
// Returns 0 (good) to 100 (bad)
func (r *RiskScorer) CalculateIPReputationScore(ip string) float64 {
	// Parse and validate IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 50.0 // Unknown IP - moderate risk
	}

	// Private/local IPs are low risk
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() {
		return 0.0
	}

	score := 0.0

	// Check Redis cache first
	cacheKey := "ip_reputation:" + ip
	if cached, err := r.redis.Client.Get(context.Background(), cacheKey).Result(); err == nil {
		var reputation IPReputationData
		if err := json.Unmarshal([]byte(cached), &reputation); err == nil {
			return r.scoreFromReputationData(&reputation)
		}
	}

	// Basic IP classification (heuristic)

	// Check for common VPN/Proxy patterns
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	if ipNet.Contains(parsedIP) {
		score += 10.0 // Private network - low risk
	}

	// TODO: Integrate with threat intelligence APIs
	// For now, use basic heuristics

	// Check if IP is from known datacenter ranges
	// This is a simplified check - production should use proper IP intelligence
	score += r.checkHostingIP(parsedIP)

	// Cache for 1 hour
	reputation := &IPReputationData{
		IPAddress:    ip,
		ThreatScore:  int(score),
		FirstSeen:    time.Now(),
		LastReported: time.Now(),
	}

	if data, err := json.Marshal(reputation); err == nil {
		r.redis.Client.Set(context.Background(), cacheKey, data, time.Hour)
	}

	return score
}

// checkHostingIP performs basic check for hosting/datacenter IPs
func (r *RiskScorer) checkHostingIP(ip net.IP) float64 {
	// This is a placeholder - production should use proper threat intelligence
	// Check against known hosting provider ranges would go here

	// For now, just check if it's in common hosting ranges
	// This is simplified - real implementation would use proper IP intelligence databases

	score := 0.0

	// If we had threat intelligence, we'd check:
	// - AbuseIPDB
	// - VirusTotal
	// - AlienVault OTX
	// - etc.

	return score
}

// scoreFromReputationData converts reputation data to a 0-100 score
func (r *RiskScorer) scoreFromReputationData(rep *IPReputationData) float64 {
	score := float64(rep.ThreatScore)

	if rep.IsTorExit {
		score = math.Max(score, 60.0)
	}
	if rep.IsVPN {
		score = math.Max(score, 30.0)
	}
	if rep.IsProxy {
		score = math.Max(score, 40.0)
	}
	if rep.IsHosting {
		score = math.Max(score, 20.0)
	}

	// Decay score based on time since last report
	if rep.ReportCount > 0 {
		daysSinceReport := time.Since(rep.LastReported).Hours() / 24
		decay := math.Min(daysSinceReport*2, 50) // Max 50 point decay
		score = score * (1 - decay/100)
	}

	return math.Max(0, math.Min(100, score))
}

// calculateDeviceScoreInternal calculates a score based on device characteristics (internal logic)
// Returns 0 (trusted/known) to 100 (unknown/suspicious)
func (r *RiskScorer) calculateDeviceScoreInternal(ctx context.Context, fingerprint DeviceFingerprint, userID string) float64 {
	if fingerprint.IsTrusted {
		return 0.0
	}

	if !fingerprint.IsKnown {
		// New device - check if it's completely new to the user
		var deviceCount int
		err := r.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM known_devices WHERE user_id = $1`,
			userID).Scan(&deviceCount)

		if err == nil && deviceCount == 0 {
			// First device ever - moderate risk
			return 15.0
		}
		// New device for existing user
		return 40.0
	}

	// Known but not trusted - slightly elevated risk
	return 10.0
}

// CalculateDeviceScore checks if device is known and calculates score
func (r *RiskScorer) CalculateDeviceScore(ctx context.Context, fingerprint DeviceFingerprint, userID string) float64 {
	// Check if device is known
	var isTrusted bool
	var lastSeen time.Time

	err := r.db.Pool.QueryRow(ctx,
		`SELECT trusted, last_seen_at FROM known_devices
		 WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint.Fingerprint).Scan(&isTrusted, &lastSeen)

	if err != nil {
		fingerprint.IsKnown = false
		fingerprint.IsTrusted = false
	} else {
		fingerprint.IsKnown = true
		fingerprint.IsTrusted = isTrusted
		fingerprint.LastSeen = lastSeen
	}

	return r.calculateDeviceScoreInternal(ctx, fingerprint, userID)
}

// CalculateGeolocationScore calculates risk based on geographic location
// Returns 0 (normal) to 100 (suspicious)
func (r *RiskScorer) CalculateGeolocationScore(ctx context.Context, lat, lng float64, userID string) float64 {
	// Invalid coordinates
	if lat == 0 && lng == 0 {
		return 10.0 // No location data - slight risk
	}

	// Check against known locations for this user
	rows, err := r.db.Pool.Query(ctx,
		`SELECT DISTINCT latitude, longitude, location
		 FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0
		 ORDER BY created_at DESC LIMIT 20`,
		userID)

	if err != nil {
		return 5.0 // Can't check - low default risk
	}
	defer rows.Close()

	knownLocations := make([]struct {
		Lat      float64
		Lng      float64
		Location string
	}, 0)

	for rows.Next() {
		var loc struct {
			Lat      float64
			Lng      float64
			Location string
		}
		if rows.Scan(&loc.Lat, &loc.Lng, &loc.Location) == nil {
			knownLocations = append(knownLocations, loc)
		}
	}

	if len(knownLocations) == 0 {
		// First login with location - slightly elevated
		return 15.0
	}

	// Check distance from known locations
	minDistance := math.MaxFloat64
	for _, known := range knownLocations {
		distance := haversineDistance(known.Lat, known.Lng, lat, lng)
		if distance < minDistance {
			minDistance = distance
		}
	}

	// Score based on distance from known locations
	if minDistance < 50 {
		return 0.0 // Within 50km - normal
	}
	if minDistance < 200 {
		return 10.0 // Within 200km - slightly unusual
	}
	if minDistance < 1000 {
		return 25.0 // Within 1000km - unusual
	}
	if minDistance < 5000 {
		return 50.0 // Long distance - very unusual
	}
	return 75.0 // Very far - extremely unusual
}

// CalculateLoginVelocityScore calculates risk based on login frequency and timing
// Returns 0 (normal) to 100 (suspicious)
func (r *RiskScorer) CalculateLoginVelocityScore(userID string, timestamp time.Time) float64 {
	ctx := context.Background()

	// Count logins in various time windows
	var last1Hour, last24Hours, last7Days int

	r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND created_at > $2`,
		userID, timestamp.Add(-1*time.Hour)).Scan(&last1Hour)

	r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND created_at > $2`,
		userID, timestamp.Add(-24*time.Hour)).Scan(&last24Hours)

	r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND created_at > $2`,
		userID, timestamp.Add(-7*24*time.Hour)).Scan(&last7Days)

	score := 0.0

	// Check for excessive login velocity
	// More than 10 logins in 1 hour is suspicious
	if last1Hour > 10 {
		score += float64(last1Hour-10) * 5
	}

	// More than 50 logins in 24 hours is very suspicious
	if last24Hours > 50 {
		score += float64(last24Hours-50) * 2
	}

	// Check for rapid successive logins (brute force pattern)
	var last5Minutes int
	r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND created_at > $2`,
		userID, timestamp.Add(-5*time.Minute)).Scan(&last5Minutes)

	if last5Minutes > 5 {
		score += float64(last5Minutes-5) * 10
	}

	// Check for logins at unusual times (off-hours)
	hour := timestamp.UTC().Hour()
	if hour < 5 || hour > 23 {
		score += 15.0 // Late night/early morning logins
	}

	return math.Min(100, score)
}

// calculateLoginVelocityScoreWithContext is a wrapper that accepts context
func (r *RiskScorer) calculateLoginVelocityScoreWithContext(ctx context.Context, userID string, timestamp time.Time) float64 {
	return r.CalculateLoginVelocityScore(userID, timestamp)
}

// DetectImpossibleTravel checks if travel between two login locations is impossible
// Returns (isImpossible, travelDuration)
func (r *RiskScorer) DetectImpossibleTravel(ctx context.Context, req ScoreRequest) (bool, time.Duration) {
	// Get the most recent successful login
	var lastLat, lastLon float64
	var lastTime time.Time

	err := r.db.Pool.QueryRow(ctx,
		`SELECT latitude, longitude, created_at FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0 AND longitude != 0
		 ORDER BY created_at DESC LIMIT 1`,
		req.UserID).Scan(&lastLat, &lastLon, &lastTime)

	if err != nil {
		return false, 0
	}

	// Calculate distance and time
	distance := haversineDistance(lastLat, lastLon, req.Latitude, req.Longitude)
	timeDelta := req.Timestamp.Sub(lastTime)

	// Calculate minimum travel time (assuming max speed aircraft)
	// Convert distance to km, speed to km/h, time to hours
	minTravelTimeHours := distance / r.MaxTravelSpeed
	minTravelTime := time.Duration(minTravelTimeHours * float64(time.Hour))

	// If actual time is less than minimum travel time, it's impossible
	if timeDelta < minTravelTime && distance > 100 {
		r.logger.Warn("Impossible travel detected",
			zap.String("user_id", req.UserID),
			zap.Float64("distance_km", distance),
			zap.Duration("actual_time", timeDelta),
			zap.Duration("min_travel_time", minTravelTime),
		)
		return true, minTravelTime - timeDelta
	}

	return false, 0
}

// detectImpossibleTravelWithDetails returns (isImpossible, distanceKm, timeDelta)
func (r *RiskScorer) detectImpossibleTravelWithDetails(ctx context.Context, req ScoreRequest) (bool, float64, time.Duration) {
	// Get the most recent successful login
	var lastLat, lastLon float64
	var lastTime time.Time

	err := r.db.Pool.QueryRow(ctx,
		`SELECT latitude, longitude, created_at FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0 AND longitude != 0
		 ORDER BY created_at DESC LIMIT 1`,
		req.UserID).Scan(&lastLat, &lastLon, &lastTime)

	if err != nil {
		return false, 0, 0
	}

	// Calculate distance and time
	distance := haversineDistance(lastLat, lastLon, req.Latitude, req.Longitude)
	timeDelta := req.Timestamp.Sub(lastTime)

	// Calculate minimum travel time (assuming max speed aircraft)
	minTravelTimeHours := distance / r.MaxTravelSpeed
	minTravelTime := time.Duration(minTravelTimeHours * float64(time.Hour))

	// If actual time is less than minimum travel time, it's impossible
	if timeDelta < minTravelTime && distance > 100 {
		r.logger.Warn("Impossible travel detected",
			zap.String("user_id", req.UserID),
			zap.Float64("distance_km", distance),
			zap.Duration("actual_time", timeDelta),
			zap.Duration("min_travel_time", minTravelTime),
		)
		return true, distance, timeDelta
	}

	return false, 0, 0
}

// DetectImpossibleTravelWithLoginEvents checks two login events for impossible travel
func (r *RiskScorer) DetectImpossibleTravelWithLoginEvents(login1, login2 LoginEvent) (bool, time.Duration) {
	if login1.Latitude == 0 || login1.Longitude == 0 ||
	   login2.Latitude == 0 || login2.Longitude == 0 {
		return false, 0
	}

	distance := haversineDistance(login1.Latitude, login1.Longitude,
	                               login2.Latitude, login2.Longitude)
	timeDelta := login2.Timestamp.Sub(login1.Timestamp)

	if timeDelta < 0 {
		return false, 0 // Invalid time order
	}

	minTravelTimeHours := distance / r.MaxTravelSpeed
	minTravelTime := time.Duration(minTravelTimeHours * float64(time.Hour))

	if timeDelta < minTravelTime && distance > 100 {
		return true, minTravelTime - timeDelta
	}

	return false, 0
}

// classifyRiskLevel converts a numeric score to a risk level category
func (r *RiskScorer) classifyRiskLevel(score int) RiskLevel {
	if score < r.LowRiskThreshold {
		return RiskLevelLow
	}
	if score < r.MediumRiskThreshold {
		return RiskLevelMedium
	}
	if score < r.HighRiskThreshold {
		return RiskLevelHigh
	}
	return RiskLevelCritical
}

// getRecommendations returns recommended actions based on risk level and factors
func (r *RiskScorer) getRecommendations(level RiskLevel, factors []RiskFactor) []string {
	actions := []string{}

	switch level {
	case RiskLevelLow:
		actions = append(actions, "Allow normal authentication flow")

	case RiskLevelMedium:
		actions = append(actions, "Require additional verification")
		actions = append(actions, "Notify user of unusual login")

	case RiskLevelHigh:
		actions = append(actions, "Require step-up authentication (MFA)")
		actions = append(actions, "Limit session duration")
		actions = append(actions, "Send security alert to user")

	case RiskLevelCritical:
		actions = append(actions, "Block authentication attempt")
		actions = append(actions, "Require administrator approval")
		actions = append(actions, "Escalate to security team")
		actions = append(actions, "Temporarily lock account")
	}

	// Add factor-specific recommendations
	for _, factor := range factors {
		switch factor.Name {
		case "impossible_travel":
			actions = append(actions, "Verify user identity through out-of-band channel")
		case "ip_reputation":
			if factor.Score > 50 {
				actions = append(actions, "Block IP address")
			}
		case "device":
			actions = append(actions, "Mark device for additional monitoring")
		}
	}

	return actions
}

// Helper methods for factor descriptions

func (r *RiskScorer) getIPReputationDescription(ip string, score float64) string {
	if score > 70 {
		return fmt.Sprintf("IP %s has high threat reputation", ip)
	}
	if score > 40 {
		return fmt.Sprintf("IP %s has moderate risk indicators", ip)
	}
	return fmt.Sprintf("IP %s has acceptable reputation", ip)
}

func (r *RiskScorer) getDeviceDescription(score float64) string {
	if score > 50 {
		return "Unknown or suspicious device"
	}
	if score > 20 {
		return "New or untrusted device"
	}
	return "Known and trusted device"
}

func (r *RiskScorer) getGeolocationDescription(score float64) string {
	if score > 50 {
		return "Login from unusual geographic location"
	}
	if score > 20 {
		return "Login from somewhat unusual location"
	}
	return "Login from normal geographic area"
}

func (r *RiskScorer) getVelocityDescription(score float64) string {
	if score > 50 {
		return "Abnormal login frequency detected"
	}
	if score > 20 {
		return "Elevated login activity"
	}
	return "Normal login pattern"
}

// durationToKm converts a time.Duration to kilometers based on MaxTravelSpeed
func (r *RiskScorer) durationToKm(d time.Duration) float64 {
	hours := d.Hours()
	return hours * r.MaxTravelSpeed
}

// SetWeights allows customization of scoring weights
func (r *RiskScorer) SetWeights(ip, device, geo, velocity, travel float64) {
	total := ip + device + geo + velocity + travel
	if total > 0 {
		// Normalize weights to sum to 1.0
		r.IPReputationWeight = ip / total
		r.DeviceScoreWeight = device / total
		r.GeolocationWeight = geo / total
		r.LoginVelocityWeight = velocity / total
		r.ImpossibleTravelWeight = travel / total
	}
}

// SetThresholds allows customization of risk level thresholds
func (r *RiskScorer) SetThresholds(low, medium, high int) {
	r.LowRiskThreshold = low
	r.MediumRiskThreshold = medium
	r.HighRiskThreshold = high
}

// SetMaxTravelSpeed sets the maximum plausible travel speed (km/h)
func (r *RiskScorer) SetMaxTravelSpeed(speedKmH float64) {
	r.MaxTravelSpeed = speedKmH
}
