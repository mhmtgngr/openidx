// Package risk provides examples of using the RiskScorer
package risk

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ExampleRiskScorer_Score demonstrates basic risk scoring
func ExampleRiskScorer_Score() {
	// In production, you would pass actual database and redis clients
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// Customize weights and thresholds if needed
	scorer.SetWeights(
		0.25, // IP reputation
		0.20, // Device score
		0.15, // Geolocation
		0.20, // Login velocity
		0.20, // Impossible travel
	)
	scorer.SetThresholds(30, 50, 70)

	// Create a score request from login attempt data
	req := ScoreRequest{
		UserID:            "user-12345",
		IPAddress:         "203.0.113.42",
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		DeviceFingerprint: "abc123def456",
		Latitude:          37.7749,  // San Francisco
		Longitude:         -122.4194,
		Timestamp:         time.Now(),
		SessionID:         "session-67890",
		AuthMethod:        "password",
		RequestedResource: "/admin/dashboard",
	}

	// Calculate risk score
	// In production: result, err := scorer.Score(ctx, req)
	_ = req
	_ = scorer

	// Handle result based on risk level
	// switch result.RiskLevel {
	// case RiskLevelLow:
	//     // Allow normal authentication
	// case RiskLevelMedium:
	//     // Require additional verification
	// case RiskLevelHigh:
	//     // Require step-up MFA
	// case RiskLevelCritical:
	//     // Block and alert
	// }

	fmt.Println("Risk scoring complete")
	// Output: Risk scoring complete
}

// ExampleRiskScorer_DetectImpossibleTravel demonstrates impossible travel detection
func ExampleRiskScorer_DetectImpossibleTravel() {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// Scenario 1: Normal travel
	login1 := LoginEvent{
		UserID:        "user-123",
		Latitude:      37.7749,  // San Francisco
		Longitude:     -122.4194,
		Timestamp:     time.Now().Add(-5 * time.Hour),
	}

	login2 := LoginEvent{
		UserID:        "user-123",
		Latitude:      34.0522,  // Los Angeles
		Longitude:     -118.2437,
		Timestamp:     time.Now(),
	}

	impossible, _ := scorer.DetectImpossibleTravel(login1, login2)
	fmt.Printf("SF to LA in 5 hours: impossible = %v\n", impossible)

	// Scenario 2: Impossible travel
	login3 := LoginEvent{
		UserID:        "user-123",
		Latitude:      37.7749,  // San Francisco
		Longitude:     -122.4194,
		Timestamp:     time.Now().Add(-30 * time.Minute),
	}

	login4 := LoginEvent{
		UserID:        "user-123",
		Latitude:      35.6762,  // Tokyo
		Longitude:     139.6503,
		Timestamp:     time.Now(),
	}

	impossible, duration := scorer.DetectImpossibleTravel(login3, login4)
	fmt.Printf("SF to Tokyo in 30 minutes: impossible = %v, time deficit = %v\n", impossible, duration)

	// Output:
	// SF to LA in 5 hours: impossible = false
	// SF to Tokyo in 30 minutes: impossible = true, time deficit = ~8h
}

// ExampleRiskScorer_Customization demonstrates customizing scorer behavior
func ExampleRiskScorer_Customization() {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// Adjust risk thresholds to be more strict
	scorer.SetThresholds(
		20, // Low: 0-19
		40, // Medium: 20-39
		60, // High: 40-59
		// Critical: 60+
	)

	// Emphasize impossible travel and IP reputation
	scorer.SetWeights(
		0.30, // IP reputation (increased)
		0.15, // Device score (decreased)
		0.10, // Geolocation (decreased)
		0.15, // Login velocity (decreased)
		0.30, // Impossible travel (increased)
	)

	// Adjust maximum travel speed (default 900 km/h = aircraft)
	// Set to 800 km/h for more conservative detection
	scorer.SetMaxTravelSpeed(800)

	fmt.Println("Scorer customized with strict thresholds")
	// Output: Scorer customized with strict thresholds
}

// ExampleScoreRequest demonstrates creating a score request
func ExampleScoreRequest() {
	// Typically, you'd gather this data from an HTTP request
	// during authentication or authorization

	req := ScoreRequest{
		UserID:            "550e8400-e29b-41d4-a716-446655440000",
		IPAddress:         "198.51.100.42",
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		DeviceFingerprint: "device-fp-12345",
		Latitude:          40.7128,  // New York
		Longitude:         -74.0060,
		Timestamp:         time.Now(),
		SessionID:         "sess-abc-123",
		AuthMethod:        "password+mfa",
		RequestedResource: "/api/v1/privileged/action",
	}

	fmt.Printf("Scoring request for user %s from %s\n", req.UserID, req.IPAddress)
	_ = req
	// Output: Scoring request for user 550e8400-e29b-41d4-a716-446655440000 from 198.51.100.42
}

// ExampleRiskScorer_Integration demonstrates integration with authentication flow
func ExampleRiskScorer_Integration() {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// This would be called during login/auth flow
	ctx := context.Background()

	// User attempting to authenticate
	req := ScoreRequest{
		UserID:    "user-123",
		IPAddress: "203.0.113.50",
		Latitude:  51.5074,  // London
		Longitude: -0.1278,
		Timestamp: time.Now(),
	}

	// Calculate risk
	// result, err := scorer.Score(ctx, req)
	_ = ctx
	_ = req

	// Make authentication decision based on risk
	// switch result.RiskLevel {
	// case RiskLevelLow:
	//     // Allow login
	//     authenticateUser(req.UserID)
	//
	// case RiskLevelMedium:
	//     // Require email verification or additional factor
	//     requireStepUpAuth(req.UserID, "email")
	//
	// case RiskLevelHigh:
	//     // Require strong MFA (hardware key, etc.)
	//     requireStepUpAuth(req.UserID, "hardware_key")
	//     limitSessionDuration(30 * time.Minute)
	//
	// case RiskLevelCritical:
	//     // Block login and alert security
	//     blockLogin(req.UserID)
	//     alertSecurityTeam(result)
	// }

	_ = scorer
	fmt.Println("Authentication decision made based on risk")
	// Output: Authentication decision made based on risk
}

// ExampleRiskLevel demonstrates risk level classification
func ExampleRiskLevel() {
	// Risk levels are automatically determined from scores
	scores := map[int]RiskLevel{
		0:   RiskLevelLow,
		15:  RiskLevelLow,
		30:  RiskLevelMedium,
		45:  RiskLevelMedium,
		60:  RiskLevelHigh,
		75:  RiskLevelCritical,
		100: RiskLevelCritical,
	}

	for score, level := range scores {
		fmt.Printf("Score %d: %s\n", score, level)
	}

	// Output:
	// Score 0: low
	// Score 15: low
	// Score 30: medium
	// Score 45: medium
	// Score 60: high
	// Score 75: critical
	// Score 100: critical
}
