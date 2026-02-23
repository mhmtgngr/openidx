// Package risk provides integration helpers for RiskScorer with existing services
package risk

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Compatibility types for the integration layer
// These map to the current scorer implementation

// ScoreRequest represents a request for risk scoring
// Alias for LoginContext to maintain API compatibility
type ScoreRequest = LoginContext

// ScoreResult represents the result of a risk score calculation
type ScoreResult struct {
	TotalScore       int             // 0-100
	RiskLevel        RiskLevel       // low/medium/high/critical
	Factors          []RiskFactor    // Individual risk factors
	RecommendActions []string        // Suggested actions
	Timestamp        time.Time       // When score was calculated
	Signals          []Signal        // Raw signals from scorer
}

// RiskFactor represents a single risk factor contributing to the score
type RiskFactor struct {
	Name        string  // Factor name
	Score       int     // Points contributed
	Description string  // Human-readable description
	Weight      float64 // Weight in overall calculation
}

// NewRiskScorer creates a new risk scorer for use in integration
func NewRiskScorer(db interface{}, redis interface{}, logger *zap.Logger) *Scorer {
	config := DefaultScorerConfig()
	return NewScorer(config, logger)
}

// ScoreLoginRequest wraps the Scorer.CalculateRiskScore method with device registration
// This is a convenience method that integrates with the existing risk service
func (s *Service) ScoreLoginRequest(ctx context.Context, userID, ip, userAgent, location string, lat, lon float64) (*ScoreResult, error) {
	// Create the scorer
	scorer := NewRiskScorer(s.db, s.redis, s.logger)

	// Generate device fingerprint
	fingerprint := s.ComputeDeviceFingerprint(ip, userAgent)

	// Get device trust level
	deviceTrustLevel := s.GetDeviceTrustLevel(ctx, userID, fingerprint)

	// Create the login context (alias for ScoreRequest)
	req := LoginContext{
		UserID:            userID,
		IPAddress:         ip,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprint,
		LoginTime:         time.Now(),
		Latitude:          lat,
		Longitude:         lon,
		DeviceTrustLevel:  deviceTrustLevel,
		CountryCode:       "",    // Will be filled by GeoIP lookup if needed
		City:              "",    // Will be filled by GeoIP lookup if needed
		FailedCount:       0,    // Will be filled by checking recent failures
		LoginCount:        1,    // Will be filled by checking recent logins
	}

	// Calculate the risk score using the new API
	assessment := scorer.CalculateRiskScore(ctx, req)

	// Convert RiskAssessment to ScoreResult for compatibility
	result := &ScoreResult{
		TotalScore: assessment.Score,
		RiskLevel:  assessment.Level,
		Timestamp:  assessment.AssessedAt,
		Signals:    assessment.Signals,
	}

	// Convert Signals to RiskFactors
	for _, signal := range assessment.Signals {
		result.Factors = append(result.Factors, RiskFactor{
			Name:        signal.Name,
			Score:       int(signal.Score),
			Description: signal.Description,
			Weight:      signal.Weight,
		})
	}

	// Add recommendation actions
	switch assessment.Recommendation {
	case RecommendationAllow:
		result.RecommendActions = []string{"Allow login"}
	case RecommendationMonitor:
		result.RecommendActions = []string{"Allow login", "Monitor session activity"}
	case RecommendationStepUpMFA:
		result.RecommendActions = []string{"Require step-up MFA", "Monitor session activity"}
	case RecommendationBlock:
		result.RecommendActions = []string{"Block login", "Alert security team"}
	}

	// Register/update the device
	deviceID, isNew, err := s.RegisterDevice(ctx, userID, fingerprint, ip, userAgent, location)
	if err != nil {
		s.logger.Warn("Failed to register device",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}

	s.logger.Info("Login risk score calculated",
		zap.String("user_id", userID),
		zap.Int("score", result.TotalScore),
		zap.String("risk_level", string(result.RiskLevel)),
		zap.Bool("new_device", isNew),
		zap.String("device_id", deviceID),
	)

	return result, nil
}

// GetRiskLevelForUser calculates the current risk level for a user's session
// This can be called periodically during a session to adjust security controls
func (s *Service) GetRiskLevelForUser(ctx context.Context, userID string, sessionStart time.Time) (RiskLevel, error) {
	_ = NewRiskScorer(s.db, s.redis, s.logger)

	// Get recent login history for this user
	history, err := s.GetLoginHistory(ctx, userID, 10)
	if err != nil {
		return RiskLevelLow, err
	}

	// If no history, low risk
	if len(history) == 0 {
		return RiskLevelLow, nil
	}

	// Check for anomalies in recent activity
	// High number of failed logins
	failedCount := 0
	for _, record := range history {
		if !record.Success {
			failedCount++
		}
	}

	if failedCount > 5 {
		return RiskLevelHigh, nil
	}

	// Check session duration - very long sessions are elevated risk
	sessionDuration := time.Since(sessionStart)
	if sessionDuration > 24*time.Hour {
		return RiskLevelMedium, nil
	}

	// Default to low risk if no issues found
	return RiskLevelLow, nil
}

// EvaluateStepUpRequired determines if step-up authentication is required
// based on the risk score and current session state
func (s *Service) EvaluateStepUpRequired(ctx context.Context, result *ScoreResult, sessionMFAEnabled bool) (bool, string) {
	// Critical risk always requires step-up
	if result.RiskLevel == RiskLevelCritical {
		return true, "critical_risk_detected"
	}

	// High risk requires step-up if not already using MFA
	if result.RiskLevel == RiskLevelHigh && !sessionMFAEnabled {
		return true, "high_risk_no_mfa"
	}

	// Medium risk with specific factors
	if result.RiskLevel == RiskLevelMedium {
		for _, factor := range result.Factors {
			if factor.Name == "new_device" || factor.Name == "unusual_location" {
				return true, "medium_risk_new_context"
			}
		}
	}

	return false, ""
}

// RecordRiskEvent logs a risk event to both the database and audit log
func (s *Service) RecordRiskEvent(ctx context.Context, userID string, result *ScoreResult, req ScoreRequest, success bool) error {
	// Extract fields from LoginContext (ScoreRequest alias)
	// Handle missing fields gracefully
	authMethod := ""
	if req.DeviceFingerprint != "" {
		authMethod = "password" // Default to password if device fingerprint is present
	}

	// Record in login_history
	s.RecordLogin(ctx,
		userID,
		req.IPAddress,
		req.UserAgent,
		"", // location will be filled by GeoIPLookup if needed
		req.Latitude,
		req.Longitude,
		req.DeviceFingerprint,
		success,
		[]string{authMethod},
		result.TotalScore,
	)

	// Log detailed risk information
	s.logger.Info("Risk event recorded",
		zap.String("user_id", userID),
		zap.Int("risk_score", result.TotalScore),
		zap.String("risk_level", string(result.RiskLevel)),
		zap.Strings("factors", extractFactorNames(result.Factors)),
		zap.Bool("success", success),
	)

	return nil
}

// extractFactorNames extracts factor names for logging
func extractFactorNames(factors []RiskFactor) []string {
	names := make([]string, len(factors))
	for i, f := range factors {
		names[i] = f.Name
	}
	return names
}

// GetRiskExplanation returns a human-readable explanation of the risk score
func (s *Service) GetRiskExplanation(result *ScoreResult) string {
	explanation := fmt.Sprintf("Risk Score: %d/100 (%s)\n\n",
		result.TotalScore,
		result.RiskLevel)

	if len(result.Factors) > 0 {
		explanation += "Contributing Factors:\n"
		for _, factor := range result.Factors {
			explanation += fmt.Sprintf("  - %s: %d points\n", factor.Description, factor.Score)
		}
	}

	if len(result.RecommendActions) > 0 {
		explanation += "\nRecommended Actions:\n"
		for _, action := range result.RecommendActions {
			explanation += fmt.Sprintf("  • %s\n", action)
		}
	}

	return explanation
}
