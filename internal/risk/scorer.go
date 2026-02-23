// Package risk provides risk scoring and assessment for authentication events
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"
)

// Signal weights for risk score calculation
const (
	WeightIPReputation   = 0.20 // 20% - IP blocklist check
	WeightDeviceTrust    = 0.20 // 20% - known vs unknown device
	WeightGeoDistance    = 0.15 // 15% - distance from usual location
	WeightLoginVelocity  = 0.15 // 15% - logins per hour
	WeightTimePattern    = 0.10 // 10% - deviation from usual hours
	WeightFailedAttempts = 0.10 // 10% - recent failures
	WeightVPNTor         = 0.10 // 10% - VPN/Tor detection
)

// RiskLevel represents the categorization of risk scores
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// Recommendation represents the action to take based on risk score
type Recommendation string

const (
	RecommendationAllow     Recommendation = "allow"
	RecommendationMonitor   Recommendation = "monitor"
	RecommendationStepUpMFA Recommendation = "step_up_mfa"
	RecommendationBlock     Recommendation = "block"
)

// Signal represents a single risk signal with its contribution to the total score
type Signal struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Score       float64 `json:"score"`       // 0-100 contribution from this signal
	Description string  `json:"description"`
	Value       any     `json:"value,omitempty"`
}

// RiskAssessment represents the complete risk assessment for a login attempt
type RiskAssessment struct {
	Score          int           `json:"score"`     // 0-100 total risk score
	Level          RiskLevel     `json:"level"`
	Signals        []Signal      `json:"signals"`
	Recommendation Recommendation `json:"recommendation"`
	AssessedAt     time.Time     `json:"assessed_at"`
	UserID         string        `json:"user_id,omitempty"`
	SessionID      string        `json:"session_id,omitempty"`
}

// LoginContext provides all available context for risk assessment
type LoginContext struct {
	UserID            string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	LoginTime         time.Time
	Latitude          float64
	Longitude         float64
	CountryCode       string
	City              string
	IsVPN             bool
	IsTor             bool
	IsProxy           bool
	DeviceTrustLevel  TrustLevel
	FailedCount       int      // recent failed attempts
	LoginCount        int      // logins in last hour
	TypicalLoginHours []int    // user's typical login hours
	TypicalCountries  []string // user's typical countries
	TypicalLocations  []GeoPoint
	LastLoginLocation *GeoPoint
	LastLoginTime     *time.Time
}

// GeoPoint represents a geographic coordinate
type GeoPoint struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country,omitempty"`
	City      string  `json:"city,omitempty"`
}

// ScorerConfig holds configuration for the risk scorer
type ScorerConfig struct {
	// IP reputation thresholds
	BlocklistScore           float64 // score if IP on blocklist (default 100)
	HighRiskCountryScore     float64 // score for high-risk country (default 50)

	// Device trust thresholds
	UnknownDeviceScore       float64 // score for unknown device (default 40)
	SuspiciousDeviceScore    float64 // score for suspicious device change (default 70)

	// Geo distance thresholds
	ImpossibleTravelScore    float64 // score for impossible travel (default 100)
	HighDistanceScore        float64 // score for high distance (default 30)
	HighDistanceThresholdKm  float64 // threshold for high distance (default 1000)

	// Login velocity thresholds
	HighVelocityScore        float64 // score for high login velocity (default 40)
	MaxLoginsPerHour         int     // threshold for high velocity (default 20)

	// Time pattern thresholds
	UnusualTimeScore         float64 // score for unusual login time (default 20)

	// Failed attempts thresholds
	FailedAttemptsScore      float64 // base score for failed attempts
	FailedAttemptsMultiplier float64 // additional score per failed attempt

	// VPN/Tor thresholds
	VPNScore                 float64 // score for VPN detection (default 30)
	TorScore                 float64 // score for Tor detection (default 60)

	// Risk level thresholds
	MediumRiskThreshold      int     // default 40
	HighRiskThreshold        int     // default 70
	CriticalRiskThreshold    int     // default 90
}

// DefaultScorerConfig returns the default scorer configuration
func DefaultScorerConfig() ScorerConfig {
	return ScorerConfig{
		BlocklistScore:           100,
		HighRiskCountryScore:     50,
		UnknownDeviceScore:       40,
		SuspiciousDeviceScore:    70,
		ImpossibleTravelScore:    100,
		HighDistanceScore:        30,
		HighDistanceThresholdKm:  1000,
		HighVelocityScore:        40,
		MaxLoginsPerHour:         20,
		UnusualTimeScore:         20,
		FailedAttemptsScore:      10,
		FailedAttemptsMultiplier: 5,
		VPNScore:                 30,
		TorScore:                 60,
		MediumRiskThreshold:      40,
		HighRiskThreshold:        70,
		CriticalRiskThreshold:    90,
	}
}

// Scorer calculates risk scores from weighted signals
type Scorer struct {
	config ScorerConfig
	logger *zap.Logger
}

// NewScorer creates a new risk scorer with the given configuration
func NewScorer(config ScorerConfig, logger *zap.Logger) *Scorer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scorer{
		config: config,
		logger: logger.With(zap.String("component", "risk_scorer")),
	}
}

// CalculateRiskScore computes a comprehensive risk score from the login context
func (s *Scorer) CalculateRiskScore(ctx context.Context, loginCtx LoginContext) *RiskAssessment {
	assessment := &RiskAssessment{
		Signals:    make([]Signal, 0, 7),
		AssessedAt: time.Now(),
		UserID:     loginCtx.UserID,
	}

	// Calculate each weighted signal
	ipRepSignal := s.calculateIPReputation(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, ipRepSignal)

	deviceSignal := s.calculateDeviceTrust(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, deviceSignal)

	geoSignal := s.calculateGeoDistance(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, geoSignal)

	velocitySignal := s.calculateLoginVelocity(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, velocitySignal)

	timeSignal := s.calculateTimePattern(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, timeSignal)

	failedSignal := s.calculateFailedAttempts(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, failedSignal)

	vpnTorSignal := s.calculateVPNOrTor(ctx, loginCtx)
	assessment.Signals = append(assessment.Signals, vpnTorSignal)

	// Sum weighted contributions to get final score (0-100)
	totalScore := 0.0
	for _, signal := range assessment.Signals {
		totalScore += signal.Score
	}

	// Cap at 100
	assessment.Score = int(math.Min(100, math.Round(totalScore)))
	assessment.Level = s.determineRiskLevel(assessment.Score)
	assessment.Recommendation = s.determineRecommendation(assessment.Score, assessment.Level)

	s.logger.Debug("Risk score calculated",
		zap.String("user_id", loginCtx.UserID),
		zap.Int("score", assessment.Score),
		zap.String("level", string(assessment.Level)),
		zap.String("recommendation", string(assessment.Recommendation)),
	)

	return assessment
}

// calculateIPReputation checks IP against blocklist (20% weight)
func (s *Scorer) calculateIPReputation(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightIPReputation
	score := 0.0
	description := "IP not on blocklist"

	// Check if IP is blocked - this would integrate with the IP threat list
	// For now, we'll check the context for any pre-computed blocklist status
	if blocked, reason := isIPBlocked(ctx, loginCtx.IPAddress); blocked {
		score = s.config.BlocklistScore * weight
		description = fmt.Sprintf("IP on blocklist: %s", reason)
	}

	return Signal{
		Name:        "ip_reputation",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       loginCtx.IPAddress,
	}
}

// calculateDeviceTrust evaluates device trust level (20% weight)
func (s *Scorer) calculateDeviceTrust(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightDeviceTrust
	score := 0.0
	description := "Device trusted"

	switch loginCtx.DeviceTrustLevel {
	case TrustLevelUnknown:
		score = s.config.UnknownDeviceScore * weight
		description = "Unknown device - first time seen"
	case TrustLevelSuspicious:
		score = s.config.SuspiciousDeviceScore * weight
		description = "Suspicious device - fingerprint changed for known device"
	case TrustLevelKnown:
		score = 10 * weight // Slight risk for known but not trusted
		description = "Known device - seen before"
	case TrustLevelTrusted:
		score = 0
		description = "Trusted device - seen 5+ times"
	}

	return Signal{
		Name:        "device_trust",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       string(loginCtx.DeviceTrustLevel),
	}
}

// calculateGeoDistance evaluates distance from usual location (15% weight)
func (s *Scorer) calculateGeoDistance(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightGeoDistance
	score := 0.0
	description := "Normal location"

	if loginCtx.LastLoginLocation != nil && loginCtx.Latitude != 0 && loginCtx.Longitude != 0 {
		distance := haversineDistance(
			loginCtx.LastLoginLocation.Latitude,
			loginCtx.LastLoginLocation.Longitude,
			loginCtx.Latitude,
			loginCtx.Longitude,
		)

		// Check for impossible travel
		if loginCtx.LastLoginTime != nil {
			timeDelta := time.Since(*loginCtx.LastLoginTime)
			speedKmh := calculateSpeed(distance, timeDelta)

			if speedKmh > 900 { // Commercial planes ~900 km/h
				score = s.config.ImpossibleTravelScore * weight
				description = fmt.Sprintf("Impossible travel: %.0f km in %.1f hours (%.0f km/h)",
					distance, timeDelta.Hours(), speedKmh)
			}
		}

		// If not impossible travel, check distance threshold
		if score == 0 && distance > s.config.HighDistanceThresholdKm {
			score = s.config.HighDistanceScore * weight
			description = fmt.Sprintf("High distance from usual location: %.0f km", distance)
		} else if score == 0 {
			description = fmt.Sprintf("Normal distance: %.0f km from usual location", distance)
		}
	}

	return Signal{
		Name:        "geo_distance",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       loginCtx.CountryCode,
	}
}

// calculateLoginVelocity evaluates login frequency (15% weight)
func (s *Scorer) calculateLoginVelocity(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightLoginVelocity
	score := 0.0
	description := "Normal login velocity"

	if loginCtx.LoginCount > s.config.MaxLoginsPerHour {
		// Scale score based on how much they exceed the threshold
		excess := float64(loginCtx.LoginCount - s.config.MaxLoginsPerHour)
		excessRatio := math.Min(excess/float64(s.config.MaxLoginsPerHour), 2.0) // Cap at 2x excess
		score = s.config.HighVelocityScore * weight * (1 + excessRatio/2)
		description = fmt.Sprintf("High login velocity: %d logins in last hour", loginCtx.LoginCount)
	} else if loginCtx.LoginCount > 0 {
		description = fmt.Sprintf("Normal login velocity: %d logins in last hour", loginCtx.LoginCount)
	}

	return Signal{
		Name:        "login_velocity",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       loginCtx.LoginCount,
	}
}

// calculateTimePattern evaluates deviation from usual login hours (10% weight)
func (s *Scorer) calculateTimePattern(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightTimePattern
	score := 0.0
	description := "Normal login time"

	loginHour := loginCtx.LoginTime.Hour()
	isUnusual := true

	if len(loginCtx.TypicalLoginHours) > 0 {
		for _, typicalHour := range loginCtx.TypicalLoginHours {
			if typicalHour == loginHour {
				isUnusual = false
				break
			}
		}
	}

	if isUnusual && len(loginCtx.TypicalLoginHours) > 0 {
		score = s.config.UnusualTimeScore * weight
		description = fmt.Sprintf("Unusual login time: %d:00 (not in typical pattern)", loginHour)
	} else if len(loginCtx.TypicalLoginHours) == 0 {
		description = "No baseline established for login time"
	} else {
		description = fmt.Sprintf("Normal login time: %d:00", loginHour)
	}

	return Signal{
		Name:        "time_pattern",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       loginHour,
	}
}

// calculateFailedAttempts evaluates recent failed login attempts (10% weight)
func (s *Scorer) calculateFailedAttempts(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightFailedAttempts
	score := 0.0
	description := "No recent failed attempts"

	if loginCtx.FailedCount > 0 {
		// Base score + multiplier for each failure
		failScore := s.config.FailedAttemptsScore + float64(loginCtx.FailedCount)*s.config.FailedAttemptsMultiplier
		// Cap the score for this signal
		failScore = math.Min(failScore, 100/weight) // Don't exceed full weight contribution
		score = failScore * weight
		description = fmt.Sprintf("%d recent failed login attempts", loginCtx.FailedCount)
	}

	return Signal{
		Name:        "failed_attempts",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value:       loginCtx.FailedCount,
	}
}

// calculateVPNOrTor evaluates VPN/Tor/proxy detection (10% weight)
func (s *Scorer) calculateVPNOrTor(ctx context.Context, loginCtx LoginContext) Signal {
	const weight = WeightVPNTor
	score := 0.0
	description := "No VPN/Tor detected"

	if loginCtx.IsTor {
		score = s.config.TorScore * weight
		description = "Tor exit node detected"
	} else if loginCtx.IsProxy {
		score = (s.config.TorScore * 0.8) * weight // Slightly less than Tor
		description = "Proxy server detected"
	} else if loginCtx.IsVPN {
		score = s.config.VPNScore * weight
		description = "VPN connection detected"
	}

	return Signal{
		Name:        "vpn_tor",
		Weight:      weight,
		Score:       score,
		Description: description,
		Value: map[string]bool{
			"vpn":   loginCtx.IsVPN,
			"tor":   loginCtx.IsTor,
			"proxy": loginCtx.IsProxy,
		},
	}
}

// determineRiskLevel categorizes the risk score into a level
func (s *Scorer) determineRiskLevel(score int) RiskLevel {
	switch {
	case score >= s.config.CriticalRiskThreshold:
		return RiskLevelCritical
	case score >= s.config.HighRiskThreshold:
		return RiskLevelHigh
	case score >= s.config.MediumRiskThreshold:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// determineRecommendation returns the recommended action based on risk score and level
func (s *Scorer) determineRecommendation(score int, level RiskLevel) Recommendation {
	switch level {
	case RiskLevelCritical:
		return RecommendationBlock
	case RiskLevelHigh:
		return RecommendationStepUpMFA
	case RiskLevelMedium:
		return RecommendationMonitor
	default:
		return RecommendationAllow
	}
}

// Helper functions

// calculateSpeed computes speed in km/h given distance in km and time delta
func calculateSpeed(distanceKm float64, timeDelta time.Duration) float64 {
	hours := timeDelta.Hours()
	if hours <= 0 {
		return 0
	}
	return distanceKm / hours
}

// isIPBlocked checks if an IP is on the blocklist
// This would integrate with the IP threat list from the database
func isIPBlocked(ctx context.Context, ip string) (bool, string) {
	// This is a placeholder - in production, this would query the database
	// or Redis for the IP threat list
	return false, ""
}

// GetSignalSummary returns a formatted summary of all signals
func (r *RiskAssessment) GetSignalSummary() string {
	if len(r.Signals) == 0 {
		return "No signals evaluated"
	}

	summary := fmt.Sprintf("Risk Score: %d (%s)\n", r.Score, r.Level)
	summary += fmt.Sprintf("Recommendation: %s\n\nSignals:\n", r.Recommendation)

	for _, signal := range r.Signals {
		summary += fmt.Sprintf("  - %s (%.0f%% weight): %.1f points - %s\n",
			signal.Name, signal.Weight*100, signal.Score, signal.Description)
	}

	return summary
}

// ToJSON converts the assessment to JSON
func (r *RiskAssessment) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// GetHighRiskSignals returns signals that contributed more than 20 points
func (r *RiskAssessment) GetHighRiskSignals() []Signal {
	var highRisk []Signal
	for _, signal := range r.Signals {
		if signal.Score >= 20 {
			highRisk = append(highRisk, signal)
		}
	}
	return highRisk
}

// String returns the string representation of the RiskLevel
func (r RiskLevel) String() string {
	return string(r)
}

// String returns the string representation of the Recommendation
func (r Recommendation) String() string {
	return string(r)
}
