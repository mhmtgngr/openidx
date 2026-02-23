// Package risk provides unit tests for the weighted signal risk scoring engine
package risk

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestCalculateRiskScore_VariousSignalCombinations tests the comprehensive risk scoring
// with various combinations of risk signals
func TestCalculateRiskScore_VariousSignalCombinations(t *testing.T) {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	baseTime := time.Now()

	tests := []struct {
		name           string
		loginCtx       LoginContext
		expectedMin    int // Minimum expected score
		expectedMax    int // Maximum expected score
		expectedLevel  RiskLevel
		expectedRec    Recommendation
	}{
		{
			name: "all_safe_signals",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "192.168.1.1",
				DeviceTrustLevel: TrustLevelTrusted,
				LoginTime:        baseTime,
				Latitude:         37.7749,
				Longitude:        -122.4194,
				FailedCount:      0,
				LoginCount:       2,
				IsVPN:            false,
				IsTor:            false,
			},
			expectedMin:   0,
			expectedMax:   20,
			expectedLevel: RiskLevelLow,
			expectedRec:   RecommendationAllow,
		},
		{
			name: "unknown_device_only",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "1.2.3.4",
				DeviceTrustLevel: TrustLevelUnknown,
				LoginTime:        baseTime,
				FailedCount:      0,
				LoginCount:       1,
				IsVPN:            false,
				IsTor:            false,
			},
			expectedMin:   30,
			expectedMax:   50,
			expectedLevel: RiskLevelLow,
			expectedRec:   RecommendationAllow,
		},
		{
			name: "tor_detected_only",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "1.2.3.4",
				DeviceTrustLevel: TrustLevelTrusted,
				LoginTime:        baseTime,
				FailedCount:      0,
				LoginCount:       1,
				IsVPN:            false,
				IsTor:            true,
			},
			expectedMin:   50,
			expectedMax:   70,
			expectedLevel: RiskLevelMedium,
			expectedRec:   RecommendationMonitor,
		},
		{
			name: "high_risk_combination",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "1.2.3.4",
				DeviceTrustLevel: TrustLevelUnknown,
				LoginTime:        baseTime,
				FailedCount:      5,
				LoginCount:       25,
				IsVPN:            true,
				IsTor:            false,
			},
			expectedMin:   60,
			expectedMax:   100,
			expectedLevel: RiskLevelHigh,
			expectedRec:   RecommendationStepUpMFA,
		},
		{
			name: "critical_risk_multiple_signals",
			loginCtx: LoginContext{
				UserID:            "user123",
				IPAddress:         "1.2.3.4",
				DeviceTrustLevel:  TrustLevelSuspicious,
				LoginTime:         baseTime,
				Latitude:          51.5074,  // London
				Longitude:         -0.1278,
				FailedCount:       10,
				LoginCount:        30,
				IsVPN:             true,
				IsTor:             false,
				LastLoginLocation: &GeoPoint{Latitude: 37.7749, Longitude: -122.4194}, // SF
				LastLoginTime:     func() *time.Time { t := baseTime.Add(-30 * time.Minute); return &t }(),
			},
			expectedMin:   90,
			expectedMax:   100,
			expectedLevel: RiskLevelCritical,
			expectedRec:   RecommendationBlock,
		},
		{
			name: "unusual_time_only",
			loginCtx: LoginContext{
				UserID:            "user123",
				IPAddress:         "1.2.3.4",
				DeviceTrustLevel:  TrustLevelTrusted,
				LoginTime:         time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC), // 3 AM
				TypicalLoginHours: []int{9, 10, 11, 14, 15, 16}, // Business hours
				FailedCount:       0,
				LoginCount:        1,
				IsVPN:             false,
				IsTor:             false,
			},
			expectedMin:   10,
			expectedMax:   30,
			expectedLevel: RiskLevelLow,
			expectedRec:   RecommendationAllow,
		},
		{
			name: "failed_attempts_only",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "1.2.3.4",
				DeviceTrustLevel: TrustLevelTrusted,
				LoginTime:        baseTime,
				FailedCount:      3,
				LoginCount:       1,
				IsVPN:            false,
				IsTor:            false,
			},
			expectedMin:   20,
			expectedMax:   40,
			expectedLevel: RiskLevelLow,
			expectedRec:   RecommendationAllow,
		},
		{
			name: "high_login_velocity",
			loginCtx: LoginContext{
				UserID:           "user123",
				IPAddress:        "1.2.3.4",
				DeviceTrustLevel: TrustLevelTrusted,
				LoginTime:        baseTime,
				FailedCount:      0,
				LoginCount:       25, // Exceeds MaxLoginsPerHour (20)
				IsVPN:            false,
				IsTor:            false,
			},
			expectedMin:   30,
			expectedMax:   60,
			expectedLevel: RiskLevelLow,
			expectedRec:   RecommendationAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := scorer.CalculateRiskScore(ctx, tt.loginCtx)

			if assessment.Score < tt.expectedMin || assessment.Score > tt.expectedMax {
				t.Errorf("Score %d outside expected range [%d, %d]",
					assessment.Score, tt.expectedMin, tt.expectedMax)
			}

			if assessment.Level != tt.expectedLevel {
				t.Errorf("Level = %v, want %v", assessment.Level, tt.expectedLevel)
			}

			if assessment.Recommendation != tt.expectedRec {
				t.Errorf("Recommendation = %v, want %v", assessment.Recommendation, tt.expectedRec)
			}

			// Verify we have all 7 signals
			if len(assessment.Signals) != 7 {
				t.Errorf("Expected 7 signals, got %d", len(assessment.Signals))
			}

			// Verify signals sum to total (approximately)
			signalSum := 0.0
			for _, signal := range assessment.Signals {
				signalSum += signal.Score
			}
			diff := float64(assessment.Score) - signalSum
			if diff < 0 {
				diff = -diff
			}
			if diff > 1 {
				t.Errorf("Signal sum %.1f doesn't match score %d", signalSum, assessment.Score)
			}
		})
	}
}

// TestSignalWeights tests that each signal has the correct weight
func TestSignalWeights(t *testing.T) {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	loginCtx := LoginContext{
		UserID:           "user123",
		IPAddress:        "1.2.3.4",
		DeviceTrustLevel: TrustLevelUnknown,
		LoginTime:        time.Now(),
	}

	assessment := scorer.CalculateRiskScore(ctx, loginCtx)

	expectedWeights := map[string]float64{
		"ip_reputation":    WeightIPReputation,
		"device_trust":     WeightDeviceTrust,
		"geo_distance":     WeightGeoDistance,
		"login_velocity":   WeightLoginVelocity,
		"time_pattern":     WeightTimePattern,
		"failed_attempts":  WeightFailedAttempts,
		"vpn_tor":          WeightVPNTor,
	}

	for _, signal := range assessment.Signals {
		expectedWeight, ok := expectedWeights[signal.Name]
		if !ok {
			t.Errorf("Unexpected signal name: %s", signal.Name)
			continue
		}
		if signal.Weight != expectedWeight {
			t.Errorf("Signal %s has weight %.2f, want %.2f",
				signal.Name, signal.Weight, expectedWeight)
		}
	}
}

// TestDetermineRiskLevel tests risk level classification
func TestDetermineRiskLevel(t *testing.T) {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())

	tests := []struct {
		score    int
		expected RiskLevel
	}{
		{0, RiskLevelLow},
		{10, RiskLevelLow},
		{39, RiskLevelLow},
		{40, RiskLevelMedium},
		{50, RiskLevelMedium},
		{69, RiskLevelMedium},
		{70, RiskLevelHigh},
		{80, RiskLevelHigh},
		{89, RiskLevelHigh},
		{90, RiskLevelCritical},
		{95, RiskLevelCritical},
		{100, RiskLevelCritical},
	}

	for _, tt := range tests {
		t.Run(tt.expected.String(), func(t *testing.T) {
			result := scorer.determineRiskLevel(tt.score)
			if result != tt.expected {
				t.Errorf("determineRiskLevel(%d) = %v, want %v",
					tt.score, result, tt.expected)
			}
		})
	}
}

// TestDetermineRecommendation tests recommendation mapping
func TestDetermineRecommendation(t *testing.T) {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())

	tests := []struct {
		score          int
		level          RiskLevel
		expected       Recommendation
	}{
		{10, RiskLevelLow, RecommendationAllow},
		{30, RiskLevelLow, RecommendationAllow},
		{45, RiskLevelMedium, RecommendationMonitor},
		{60, RiskLevelMedium, RecommendationMonitor},
		{75, RiskLevelHigh, RecommendationStepUpMFA},
		{85, RiskLevelHigh, RecommendationStepUpMFA},
		{95, RiskLevelCritical, RecommendationBlock},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := scorer.determineRecommendation(tt.score, tt.level)
			if result != tt.expected {
				t.Errorf("determineRecommendation(%d, %s) = %v, want %v",
					tt.score, tt.level, result, tt.expected)
			}
		})
	}
}

// TestCalculateSpeed tests speed calculation
func TestCalculateSpeed(t *testing.T) {
	tests := []struct {
		name         string
		distanceKm   float64
		timeDelta    time.Duration
		expectedKmh  float64
	}{
		{
			name:        "100km in 1 hour",
			distanceKm:  100,
			timeDelta:   1 * time.Hour,
			expectedKmh: 100,
		},
		{
			name:        "500km in 30 minutes",
			distanceKm:  500,
			timeDelta:   30 * time.Minute,
			expectedKmh: 1000,
		},
		{
			name:        "1000km in 2 hours",
			distanceKm:  1000,
			timeDelta:   2 * time.Hour,
			expectedKmh: 500,
		},
		{
			name:        "zero time",
			distanceKm:  100,
			timeDelta:   0,
			expectedKmh: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateSpeed(tt.distanceKm, tt.timeDelta)
			if result != tt.expectedKmh {
				t.Errorf("calculateSpeed(%v, %v) = %v km/h, want %v km/h",
					tt.distanceKm, tt.timeDelta, result, tt.expectedKmh)
			}
		})
	}
}

// TestRiskAssessment_GetSignalSummary tests signal summary generation
func TestRiskAssessment_GetSignalSummary(t *testing.T) {
	assessment := &RiskAssessment{
		Score:      65,
		Level:      RiskLevelHigh,
		Signals: []Signal{
			{Name: "ip_reputation", Weight: 0.20, Score: 0, Description: "IP not on blocklist"},
			{Name: "device_trust", Weight: 0.20, Score: 40, Description: "Unknown device"},
			{Name: "failed_attempts", Weight: 0.10, Score: 25, Description: "3 failed attempts"},
		},
		Recommendation: RecommendationStepUpMFA,
		AssessedAt:     time.Now(),
	}

	summary := assessment.GetSignalSummary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	// Check for key components
	expectedStrings := []string{
		"Risk Score: 65",
		"high",
		"step_up_mfa",
		"ip_reputation",
		"device_trust",
		"failed_attempts",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(summary, expected) {
			t.Errorf("Summary should contain '%s'", expected)
		}
	}
}

// TestRiskAssessment_GetHighRiskSignals tests filtering high risk signals
func TestRiskAssessment_GetHighRiskSignals(t *testing.T) {
	assessment := &RiskAssessment{
		Score: 75,
		Signals: []Signal{
			{Name: "low_risk", Score: 5},
			{Name: "medium_risk", Score: 15},
			{Name: "high_risk1", Score: 25},
			{Name: "high_risk2", Score: 30},
		},
	}

	highRisk := assessment.GetHighRiskSignals()

	if len(highRisk) != 2 {
		t.Errorf("Expected 2 high risk signals, got %d", len(highRisk))
	}

	for _, signal := range highRisk {
		if signal.Score < 20 {
			t.Errorf("Signal %s has score %.1f, should be >= 20", signal.Name, signal.Score)
		}
	}
}

// TestScorerConfig_CustomThresholds tests custom risk thresholds
func TestScorerConfig_CustomThresholds(t *testing.T) {
	config := ScorerConfig{
		MediumRiskThreshold:   30,
		HighRiskThreshold:     60,
		CriticalRiskThreshold: 85,
	}
	scorer := NewScorer(config, zap.NewNop())

	tests := []struct {
		score    int
		expected RiskLevel
	}{
		{20, RiskLevelLow},
		{35, RiskLevelMedium},
		{65, RiskLevelHigh},
		{90, RiskLevelCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := scorer.determineRiskLevel(tt.score)
			if result != tt.expected {
				t.Errorf("Custom threshold test failed: %d -> %v, want %v",
					tt.score, result, tt.expected)
			}
		})
	}
}

// Helper functions

func containsAbs(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelperAbs(s, substr))
}

func containsHelperAbs(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
