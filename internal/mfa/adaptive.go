// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// Redis key prefixes for adaptive MFA tracking
	redisKnownDevicePrefix   = "mfa:adaptive:device:"
	redisKnownIPPrefix       = "mfa:adaptive:ip:"
	redisKnownLocationPrefix = "mfa:adaptive:location:"
	redisFailedLoginPrefix   = "mfa:adaptive:failed:"
	redisLoginPatternPrefix  = "mfa:adaptive:pattern:"

	// TTLs for tracking data
	knownDeviceTTL   = 30 * 24 * time.Hour // 30 days
	knownIPTTL       = 7 * 24 * time.Hour  // 7 days
	knownLocationTTL = 7 * 24 * time.Hour  // 7 days
	failedLoginTTL   = 1 * time.Hour       // 1 hour
	loginPatternTTL  = 90 * 24 * time.Hour // 90 days
)

// AuthSignal represents the authentication signals used for risk evaluation
type AuthSignal struct {
	UserID          uuid.UUID `json:"user_id"`
	IPAddress       string    `json:"ip_address"`
	UserAgent       string    `json:"user_agent"`
	DeviceID        string    `json:"device_id"`        // Browser/device fingerprint
	Location        string    `json:"location"`         // Country/City
	Timestamp       time.Time `json:"timestamp"`
	LoginTimeNormal bool      `json:"login_time_normal"` // Within normal login hours
	IsNewDevice     bool      `json:"is_new_device"`
	IsNewIP         bool      `json:"is_new_ip"`
	IsNewLocation   bool      `json:"is_new_location"`
}

// RiskScore represents the result of a risk evaluation
type RiskScore struct {
	Score        int       `json:"score"`         // 0-100
	Level        RiskLevel `json:"level"`         // LOW, MEDIUM, HIGH, CRITICAL
	RequiredMFA  MFAType   `json:"required_mfa"`  // NONE, TOTP, WEBAUTHN, BLOCK
	Reasons      []string  `json:"reasons"`       // Human-readable explanations
	EvaluatedAt  time.Time `json:"evaluated_at"`
}

// RiskLevel represents the risk category
type RiskLevel string

const (
	RiskLevelLow       RiskLevel = "LOW"
	RiskLevelMedium    RiskLevel = "MEDIUM"
	RiskLevelHigh      RiskLevel = "HIGH"
	RiskLevelCritical  RiskLevel = "CRITICAL"
)

// MFAType represents the type of MFA required
type MFAType string

const (
	MFANone     MFAType = "NONE"      // Skip MFA
	MFATOTP     MFAType = "TOTP"      // Require TOTP
	MFAWebAuthn MFAType = "WEBAUTHN"  // Require WebAuthn/hardware key
	MFABlock    MFAType = "BLOCK"     // Block and alert admin
)

// AdaptivePolicyConfig holds configuration for adaptive MFA
type AdaptivePolicyConfig struct {
	LowRiskThreshold      int  // Below this: skip MFA (default: 30)
	MediumRiskThreshold   int  // Below this: standard MFA (default: 70) - TOTP
	HighRiskThreshold     int  // Below this: strong MFA (default: 90) - WebAuthn
	// At or above high_risk_threshold: block + admin notification

	NewDeviceRiskScore       int // Risk score for new device (default: 30)
	NewLocationRiskScore     int // Risk score for new location (default: 20)
	NewIPRiskScore           int // Risk score for new IP (default: 15)
	FailedLoginRiskScore     int // Risk score per recent failed login (default: 10)
	ImpossibleTravelScore    int // Risk score for impossible travel (default: 50)
	BlockedIPRiskScore       int // Risk score for blocked IP (default: 40)
	AbnormalTimeRiskScore    int // Risk score for abnormal login time (default: 15)

	FailedLoginWindow    time.Duration // Time window to count failed logins (default: 1 hour)
	MaxFailedLogins      int           // Max failed logins before adding risk (default: 3)

	NormalLoginHourStart int // Start of normal login hours (24h format, default: 6)
	NormalLoginHourEnd   int // End of normal login hours (24h format, default: 22)
}

// DefaultAdaptivePolicyConfig returns the default adaptive policy configuration
func DefaultAdaptivePolicyConfig() *AdaptivePolicyConfig {
	return &AdaptivePolicyConfig{
		LowRiskThreshold:      30,
		MediumRiskThreshold:   70,
		HighRiskThreshold:     90,
		NewDeviceRiskScore:    30,
		NewLocationRiskScore:  20,
		NewIPRiskScore:        15,
		FailedLoginRiskScore:  10,
		ImpossibleTravelScore: 50,
		BlockedIPRiskScore:    100, // Blocked IP should always be critical
		AbnormalTimeRiskScore: 15,
		FailedLoginWindow:     1 * time.Hour,
		MaxFailedLogins:       3,
		NormalLoginHourStart:  6,
		NormalLoginHourEnd:    22,
	}
}

// AdaptiveService provides risk-based MFA evaluation
type AdaptiveService struct {
	config     *AdaptivePolicyConfig
	redis      RedisClient
	logger     *zap.Logger
	blockedIPs map[string]bool // Set of blocked IP addresses
}

// NewAdaptiveService creates a new adaptive MFA service
func NewAdaptiveService(logger *zap.Logger, redis RedisClient, config *AdaptivePolicyConfig) *AdaptiveService {
	if config == nil {
		config = DefaultAdaptivePolicyConfig()
	}

	return &AdaptiveService{
		config:     config,
		redis:      redis,
		logger:     logger,
		blockedIPs: make(map[string]bool),
	}
}

// EvaluateRisk evaluates the risk level for an authentication attempt
// and returns the appropriate MFA requirement
func (s *AdaptiveService) EvaluateRisk(ctx context.Context, signal *AuthSignal) (*RiskScore, error) {
	score := 0
	reasons := make([]string, 0)

	// Check if IP is blocked
	if s.isIPBlocked(signal.IPAddress) {
		score += s.config.BlockedIPRiskScore
		reasons = append(reasons, fmt.Sprintf("IP address %s is blocked", signal.IPAddress))
	}

	// Check for new device
	if signal.IsNewDevice {
		score += s.config.NewDeviceRiskScore
		reasons = append(reasons, "New device detected")
	}

	// Check for new IP
	if signal.IsNewIP {
		score += s.config.NewIPRiskScore
		reasons = append(reasons, fmt.Sprintf("New IP address: %s", signal.IPAddress))
	}

	// Check for new location
	if signal.IsNewLocation {
		score += s.config.NewLocationRiskScore
		reasons = append(reasons, fmt.Sprintf("New location: %s", signal.Location))
	}

	// Check for abnormal login time
	if !signal.LoginTimeNormal {
		score += s.config.AbnormalTimeRiskScore
		hour := signal.Timestamp.Hour()
		reasons = append(reasons, fmt.Sprintf("Login at abnormal time: %02d:00", hour))
	}

	// Check recent failed login attempts
	failedCount, err := s.getRecentFailedLogins(ctx, signal.UserID)
	if err != nil {
		s.logger.Warn("Failed to get recent failed logins",
			zap.String("user_id", signal.UserID.String()),
			zap.Error(err),
		)
	} else if failedCount > s.config.MaxFailedLogins {
		additionalScore := (failedCount - s.config.MaxFailedLogins) * s.config.FailedLoginRiskScore
		score += additionalScore
		reasons = append(reasons, fmt.Sprintf("%d recent failed login attempts", failedCount))
	}

	// Check for impossible travel (login from distant location within short time)
	if impossible, err := s.checkImpossibleTravel(ctx, signal); err == nil && impossible {
		score += s.config.ImpossibleTravelScore
		reasons = append(reasons, "Impossible travel detected (login from distant location)")
	}

	// Determine risk level and required MFA
	level, requiredMFA := s.determineRiskLevel(score)

	result := &RiskScore{
		Score:       score,
		Level:       level,
		RequiredMFA: requiredMFA,
		Reasons:     reasons,
		EvaluatedAt: time.Now(),
	}

	s.logger.Info("Risk evaluation completed",
		zap.String("user_id", signal.UserID.String()),
		zap.Int("score", score),
		zap.String("level", string(level)),
		zap.String("required_mfa", string(requiredMFA)),
	)

	return result, nil
}

// determineRiskLevel maps a risk score to a risk level and MFA requirement
// Rules:
// - score < LowRiskThreshold (30): skip MFA
// - score >= LowRiskThreshold (30) and < MediumRiskThreshold (70): require TOTP
// - score >= MediumRiskThreshold (70) and < HighRiskThreshold (90): require WebAuthn
// - score >= HighRiskThreshold (90): block and alert admin
func (s *AdaptiveService) determineRiskLevel(score int) (RiskLevel, MFAType) {
	if score >= s.config.HighRiskThreshold {
		return RiskLevelCritical, MFABlock
	}
	if score >= s.config.MediumRiskThreshold {
		return RiskLevelHigh, MFAWebAuthn
	}
	if score >= s.config.LowRiskThreshold {
		return RiskLevelMedium, MFATOTP
	}
	return RiskLevelLow, MFANone
}

// RecordSuccessfulLogin records a successful login for adaptive learning
func (s *AdaptiveService) RecordSuccessfulLogin(ctx context.Context, signal *AuthSignal) error {
	userID := signal.UserID.String()

	// Store known device
	if signal.DeviceID != "" {
		key := s.buildDeviceKey(userID, signal.DeviceID)
		if err := s.redis.Set(ctx, key, "1", knownDeviceTTL).Err(); err != nil {
			s.logger.Error("Failed to store known device",
				zap.String("user_id", userID),
				zap.Error(err),
			)
		}
	}

	// Store known IP
	if signal.IPAddress != "" {
		key := s.buildIPKey(userID, signal.IPAddress)
		if err := s.redis.Set(ctx, key, "1", knownIPTTL).Err(); err != nil {
			s.logger.Error("Failed to store known IP",
				zap.String("user_id", userID),
				zap.Error(err),
			)
		}
	}

	// Store known location
	if signal.Location != "" {
		key := s.buildLocationKey(userID, signal.Location)
		if err := s.redis.Set(ctx, key, "1", knownLocationTTL).Err(); err != nil {
			s.logger.Error("Failed to store known location",
				zap.String("user_id", userID),
				zap.Error(err),
			)
		}
	}

	// Store login pattern (hour of day)
	patternKey := s.buildPatternKey(userID)
	hour := signal.Timestamp.Hour()
	if err := s.redis.Set(ctx, patternKey, hour, loginPatternTTL).Err(); err != nil {
		s.logger.Error("Failed to store login pattern",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}

	// Clear failed login counter
	failedKey := s.buildFailedLoginKey(userID)
	if err := s.redis.Del(ctx, failedKey).Err(); err != nil {
		s.logger.Warn("Failed to clear failed login counter",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}

	return nil
}

// RecordFailedLogin records a failed login attempt
func (s *AdaptiveService) RecordFailedLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	key := s.buildFailedLoginKey(userID.String())

	// Increment failed login counter
	result := s.redis.Get(ctx, key)
	count := 0

	if result.Err() == nil {
		fmt.Sscanf(result.Val(), "%d", &count)
	}

	count++

	// Store with TTL
	if err := s.redis.Set(ctx, key, fmt.Sprintf("%d", count), s.config.FailedLoginWindow).Err(); err != nil {
		return fmt.Errorf("failed to record failed login: %w", err)
	}

	s.logger.Warn("Failed login recorded",
		zap.String("user_id", userID.String()),
		zap.String("ip", ipAddress),
		zap.Int("count", count),
	)

	return nil
}

// GetSignalInfo analyzes authentication signals and populates the AuthSignal
func (s *AdaptiveService) GetSignalInfo(ctx context.Context, userID uuid.UUID, ipAddress, deviceID, location string, timestamp time.Time) (*AuthSignal, error) {
	signal := &AuthSignal{
		UserID:    userID,
		IPAddress: ipAddress,
		DeviceID:  deviceID,
		Location:  location,
		Timestamp: timestamp,
	}

	userIDStr := userID.String()

	// Check if device is known
	if deviceID != "" {
		key := s.buildDeviceKey(userIDStr, deviceID)
		_, err := s.redis.Get(ctx, key).Result()
		signal.IsNewDevice = err == redis.Nil
	} else {
		signal.IsNewDevice = true // No device ID provided, treat as new
	}

	// Check if IP is known
	if ipAddress != "" {
		key := s.buildIPKey(userIDStr, ipAddress)
		_, err := s.redis.Get(ctx, key).Result()
		signal.IsNewIP = err == redis.Nil
	} else {
		signal.IsNewIP = true
	}

	// Check if location is known
	if location != "" {
		key := s.buildLocationKey(userIDStr, location)
		_, err := s.redis.Get(ctx, key).Result()
		signal.IsNewLocation = err == redis.Nil
	} else {
		signal.IsNewLocation = true
	}

	// Check if login time is normal
	signal.LoginTimeNormal = s.isNormalLoginTime(timestamp)

	return signal, nil
}

// isNormalLoginTime checks if the login time is within normal hours
func (s *AdaptiveService) isNormalLoginTime(t time.Time) bool {
	hour := t.Hour()

	// Handle case where end hour is before start hour (e.g., 22:00 to 06:00)
	if s.config.NormalLoginHourEnd < s.config.NormalLoginHourStart {
		return hour >= s.config.NormalLoginHourStart || hour <= s.config.NormalLoginHourEnd
	}

	return hour >= s.config.NormalLoginHourStart && hour <= s.config.NormalLoginHourEnd
}

// checkImpossibleTravel checks for impossible travel (logins from distant locations within short time)
func (s *AdaptiveService) checkImpossibleTravel(ctx context.Context, signal *AuthSignal) (bool, error) {
	if signal.Location == "" {
		return false, nil
	}

	// Get the last login location for this user
	// This would require storing last login location per user
	// For now, this is a placeholder for the actual implementation
	// In a full implementation, you would:
	// 1. Store last login location and timestamp
	// 2. Calculate distance between current and last location
	// 3. Calculate time elapsed
	// 4. Check if travel was physically possible

	return false, nil
}

// getRecentFailedLogins gets the count of recent failed login attempts
func (s *AdaptiveService) getRecentFailedLogins(ctx context.Context, userID uuid.UUID) (int, error) {
	key := s.buildFailedLoginKey(userID.String())

	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return 0, nil
	}
	if result.Err() != nil {
		return 0, fmt.Errorf("redis error: %w", result.Err())
	}

	var count int
	if _, err := fmt.Sscanf(result.Val(), "%d", &count); err != nil {
		return 0, nil
	}

	return count, nil
}

// AddBlockedIP adds an IP address to the blocked list
func (s *AdaptiveService) AddBlockedIP(ip string) {
	s.blockedIPs[ip] = true
	s.logger.Info("IP address added to blocked list", zap.String("ip", ip))
}

// RemoveBlockedIP removes an IP address from the blocked list
func (s *AdaptiveService) RemoveBlockedIP(ip string) {
	delete(s.blockedIPs, ip)
	s.logger.Info("IP address removed from blocked list", zap.String("ip", ip))
}

// isIPBlocked checks if an IP address is blocked
func (s *AdaptiveService) isIPBlocked(ip string) bool {
	return s.blockedIPs[ip]
}

// Redis key builders
func (s *AdaptiveService) buildDeviceKey(userID, deviceID string) string {
	return fmt.Sprintf("%s%s:%s", redisKnownDevicePrefix, userID, deviceID)
}

func (s *AdaptiveService) buildIPKey(userID, ip string) string {
	return fmt.Sprintf("%s%s:%s", redisKnownIPPrefix, userID, ip)
}

func (s *AdaptiveService) buildLocationKey(userID, location string) string {
	return fmt.Sprintf("%s%s:%s", redisKnownLocationPrefix, userID, location)
}

func (s *AdaptiveService) buildFailedLoginKey(userID string) string {
	return fmt.Sprintf("%s%s", redisFailedLoginPrefix, userID)
}

func (s *AdaptiveService) buildPatternKey(userID string) string {
	return fmt.Sprintf("%s%s:hour", redisLoginPatternPrefix, userID)
}

// ShouldSkipMFA determines if MFA can be skipped based on risk evaluation
func (s *AdaptiveService) ShouldSkipMFA(ctx context.Context, signal *AuthSignal) (bool, *RiskScore, error) {
	risk, err := s.EvaluateRisk(ctx, signal)
	if err != nil {
		return false, nil, err
	}

	return risk.RequiredMFA == MFANone, risk, nil
}

// GetRequiredMFA returns the MFA type required for a given authentication signal
func (s *AdaptiveService) GetRequiredMFA(ctx context.Context, signal *AuthSignal) (MFAType, *RiskScore, error) {
	risk, err := s.EvaluateRisk(ctx, signal)
	if err != nil {
		return MFATOTP, nil, err
	}

	return risk.RequiredMFA, risk, nil
}
