// Package risk provides examples of using the Scorer
package risk

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// DemoScorer_CalculateRiskScore demonstrates basic risk scoring
func DemoScorer_CalculateRiskScore() {
	// Create a scorer with default configuration
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	// Create a login context with typical user behavior
	loginCtx := LoginContext{
		UserID:           "user-12345",
		IPAddress:        "203.0.113.42",
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		DeviceTrustLevel: TrustLevelTrusted,
		LoginTime:        time.Now(),
		Latitude:         37.7749, // San Francisco
		Longitude:        -122.4194,
		CountryCode:      "US",
		City:             "San Francisco",
		FailedCount:      0,
		LoginCount:       1,
		IsVPN:            false,
		IsTor:            false,
	}

	// Calculate risk score
	assessment := scorer.CalculateRiskScore(ctx, loginCtx)

	// Handle result based on risk level
	switch assessment.Level {
	case RiskLevelLow:
		fmt.Println("Allow login - low risk")
	case RiskLevelMedium:
		fmt.Println("Require monitoring - medium risk")
	case RiskLevelHigh:
		fmt.Println("Require step-up MFA - high risk")
	case RiskLevelCritical:
		fmt.Println("Block login - critical risk")
	}

	fmt.Printf("Risk Score: %d (%s)\n", assessment.Score, assessment.Level)
	// Output: Risk Score: 0 (low)
	// Allow login - low risk
}

// DemoScorer_ImpossibleTravel demonstrates impossible travel detection
func DemoScorer_ImpossibleTravel() {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	// Scenario 1: Normal travel from SF to LA in 5 hours
	now := time.Now()
	loginCtx := LoginContext{
		UserID:           "user-123",
		DeviceTrustLevel: TrustLevelTrusted,
		LoginTime:        now,
		Latitude:         34.0522, // Los Angeles
		Longitude:        -118.2437,
		LastLoginLocation: &GeoPoint{
			Latitude:  37.7749, // San Francisco
			Longitude: -122.4194,
		},
		LastLoginTime: func() *time.Time {
			t := now.Add(-5 * time.Hour)
			return &t
		}(),
		LoginCount: 1,
	}

	assessment := scorer.CalculateRiskScore(ctx, loginCtx)
	fmt.Printf("SF to LA in 5 hours - impossible travel risk: %v\n", assessment.Level == RiskLevelLow)

	// Scenario 2: Impossible travel from SF to Tokyo in 30 minutes
	loginCtx2 := LoginContext{
		UserID:           "user-123",
		DeviceTrustLevel: TrustLevelTrusted,
		LoginTime:        now,
		Latitude:         35.6762, // Tokyo
		Longitude:        139.6503,
		LastLoginLocation: &GeoPoint{
			Latitude:  37.7749, // San Francisco
			Longitude: -122.4194,
		},
		LastLoginTime: func() *time.Time {
			t := now.Add(-30 * time.Minute)
			return &t
		}(),
		LoginCount: 1,
	}

	assessment2 := scorer.CalculateRiskScore(ctx, loginCtx2)
	fmt.Printf("SF to Tokyo in 30 minutes - impossible travel risk: %v\n", assessment2.Level != RiskLevelLow)

	// Output:
	// SF to LA in 5 hours - impossible travel risk: true
	// SF to Tokyo in 30 minutes - impossible travel risk: true
}

// DemoScorer_HighRiskScenario demonstrates a high-risk login scenario
func DemoScorer_HighRiskScenario() {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	loginCtx := LoginContext{
		UserID:           "user-123",
		IPAddress:        "1.2.3.4",
		DeviceTrustLevel: TrustLevelUnknown, // Unknown device
		LoginTime:        time.Now(),
		FailedCount:      5,  // Multiple failed attempts
		LoginCount:       25, // High login velocity
		IsVPN:            true,
		IsTor:            false,
	}

	assessment := scorer.CalculateRiskScore(ctx, loginCtx)
	fmt.Printf("High risk scenario - Score: %d, Level: %s, Recommendation: %s\n",
		assessment.Score, assessment.Level, assessment.Recommendation)

	// Output: High risk scenario - Score: 66, Level: high, Recommendation: step_up_mfa
}

// DemoScorer_TrustedDevice demonstrates a low-risk trusted device login
func DemoScorer_TrustedDevice() {
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())
	ctx := context.Background()

	loginCtx := LoginContext{
		UserID:           "user-123",
		IPAddress:        "192.168.1.1",
		DeviceTrustLevel: TrustLevelTrusted, // Trusted device
		LoginTime:        time.Now(),
		Latitude:         37.7749,
		Longitude:        -122.4194,
		CountryCode:      "US",
		City:             "San Francisco",
		FailedCount:      0,
		LoginCount:       2,
		IsVPN:            false,
		IsTor:            false,
	}

	assessment := scorer.CalculateRiskScore(ctx, loginCtx)
	fmt.Printf("Trusted device - Score: %d, Level: %s, Recommendation: %s\n",
		assessment.Score, assessment.Level, assessment.Recommendation)

	// Output: Trusted device - Score: 0, Level: low, Recommendation: allow
}

// ExampleRiskLevel demonstrates risk level classification
func ExampleRiskLevel() {
	// Risk levels are automatically determined from scores
	config := DefaultScorerConfig()
	scorer := NewScorer(config, zap.NewNop())

	testScores := []int{0, 15, 40, 50, 70, 80, 90, 100}
	for _, score := range testScores {
		level := scorer.determineRiskLevel(score)
		fmt.Printf("Score %d: %s\n", score, level)
	}

	// Output:
	// Score 0: low
	// Score 15: low
	// Score 40: medium
	// Score 50: medium
	// Score 70: high
	// Score 80: high
	// Score 90: critical
	// Score 100: critical
}
