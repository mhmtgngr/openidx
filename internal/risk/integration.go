// Package risk provides integration helpers for RiskScorer with existing services
package risk

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ScoreLoginRequest wraps the RiskScorer.Score method with device registration
// This is a convenience method that integrates with the existing risk service
func (s *Service) ScoreLoginRequest(ctx context.Context, userID, ip, userAgent, location string, lat, lon float64) (*ScoreResult, error) {
	// Create the scorer if not already created
	scorer := NewRiskScorer(s.db, s.redis, s.logger)

	// Generate device fingerprint
	fingerprint := s.ComputeDeviceFingerprint(ip, userAgent)

	// Create the score request
	req := ScoreRequest{
		UserID:            userID,
		IPAddress:         ip,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprint,
		Latitude:          lat,
		Longitude:         lon,
		Timestamp:         time.Now(),
	}

	// Calculate the risk score
	result, err := scorer.Score(ctx, req)
	if err != nil {
		s.logger.Error("Failed to calculate risk score",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return nil, err
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
		[]string{req.AuthMethod},
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
