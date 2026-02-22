// Package risk provides risk assessment and scoring tests
package risk

import (
	"context"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
)

// Mock database and redis for testing
type mockDB struct {
	*database.PostgresDB
}

type mockRedis struct {
	*database.RedisClient
}

func TestRiskScorer_Score(t *testing.T) {
	// This would require a proper test database setup
	// For now, we'll test the basic structure

	scorer := &RiskScorer{
		db:         nil, // Would use mock
		redis:      nil, // Would use mock
		logger:     zap.NewNop(),
		httpClient: nil,
	}

	// Test basic request structure
	req := ScoreRequest{
		UserID:            "test-user-123",
		IPAddress:         "192.168.1.1",
		UserAgent:         "Mozilla/5.0",
		DeviceFingerprint: "abc123",
		Latitude:          37.7749,
		Longitude:         -122.4194,
		Timestamp:         time.Now(),
	}

	// Would test scoring here
	_ = scorer
	_ = req
}

func TestCalculateIPReputationScore(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	tests := []struct {
		name     string
		ip       string
		expected float64
	}{
		{
			name:     "localhost",
			ip:       "127.0.0.1",
			expected: 0.0,
		},
		{
			name:     "private IP",
			ip:       "192.168.1.1",
			expected: 0.0,
		},
		{
			name:     "private IP 10.x",
			ip:       "10.0.0.1",
			expected: 0.0,
		},
		{
			name:     "link-local",
			ip:       "169.254.1.1",
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scorer.CalculateIPReputationScore(tt.ip)
			if score != tt.expected {
				t.Errorf("CalculateIPReputationScore() = %v, want %v", score, tt.expected)
			}
		})
	}
}

func TestClassifyRiskLevel(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	tests := []struct {
		score    int
		expected RiskLevel
	}{
		{0, RiskLevelLow},
		{10, RiskLevelLow},
		{29, RiskLevelLow},
		{30, RiskLevelMedium},
		{40, RiskLevelMedium},
		{49, RiskLevelMedium},
		{50, RiskLevelHigh},
		{60, RiskLevelHigh},
		{69, RiskLevelHigh},
		{70, RiskLevelCritical},
		{85, RiskLevelCritical},
		{100, RiskLevelCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := scorer.classifyRiskLevel(tt.score)
			if result != tt.expected {
				t.Errorf("classifyRiskLevel(%d) = %v, want %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestDetectImpossibleTravel(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	tests := []struct {
		name          string
		login1        LoginEvent
		login2        LoginEvent
		expected      bool
		minTravelDiff time.Duration
	}{
		{
			name: "normal travel - San Francisco to Los Angeles",
			login1: LoginEvent{
				UserID:    "user1",
				Latitude:  37.7749,  // San Francisco
				Longitude: -122.4194,
				Timestamp: time.Now().Add(-2 * time.Hour),
			},
			login2: LoginEvent{
				UserID:    "user1",
				Latitude:  34.0522,  // Los Angeles
				Longitude: -118.2437,
				Timestamp: time.Now(),
			},
			expected: false,
		},
		{
			name: "normal travel - short time, short distance",
			login1: LoginEvent{
				UserID:    "user1",
				Latitude:  37.7749,
				Longitude: -122.4194,
				Timestamp: time.Now().Add(-30 * time.Minute),
			},
			login2: LoginEvent{
				UserID:    "user1",
				Latitude:  37.8044,  // Nearby in SF
				Longitude: -122.2711,
				Timestamp: time.Now(),
			},
			expected: false,
		},
		{
			name: "impossible travel - San Francisco to Tokyo in 1 hour",
			login1: LoginEvent{
				UserID:    "user1",
				Latitude:  37.7749,  // San Francisco
				Longitude: -122.4194,
				Timestamp: time.Now().Add(-1 * time.Hour),
			},
			login2: LoginEvent{
				UserID:    "user1",
				Latitude:  35.6762,  // Tokyo
				Longitude: 139.6503,
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name: "impossible travel - New York to London in 30 minutes",
			login1: LoginEvent{
				UserID:    "user1",
				Latitude:  40.7128,  // New York
				Longitude: -74.0060,
				Timestamp: time.Now().Add(-30 * time.Minute),
			},
			login2: LoginEvent{
				UserID:    "user1",
				Latitude:  51.5074,  // London
				Longitude: -0.1278,
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name: "invalid coordinates - should return false",
			login1: LoginEvent{
				UserID:    "user1",
				Latitude:  0,
				Longitude: 0,
				Timestamp: time.Now().Add(-1 * time.Hour),
			},
			login2: LoginEvent{
				UserID:    "user1",
				Latitude:  37.7749,
				Longitude: -122.4194,
				Timestamp: time.Now(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impossible, duration := scorer.DetectImpossibleTravel(tt.login1, tt.login2)
			if impossible != tt.expected {
				t.Errorf("DetectImpossibleTravel() impossible = %v, want %v", impossible, tt.expected)
			}
			if tt.expected && duration <= 0 {
				t.Errorf("DetectImpossibleTravel() returned true but duration = %v, expected > 0", duration)
			}
		})
	}
}

func TestHaversineDistance(t *testing.T) {
	tests := []struct {
		name     string
		lat1     float64
		lon1     float64
		lat2     float64
		lon2     float64
		expected float64 // Approximate distance in km
		tolerance float64
	}{
		{
			name:     "San Francisco to Los Angeles",
			lat1:     37.7749,
			lon1:     -122.4194,
			lat2:     34.0522,
			lon2:     -118.2437,
			expected: 559,
			tolerance: 10,
		},
		{
			name:     "New York to London",
			lat1:     40.7128,
			lon1:     -74.0060,
			lat2:     51.5074,
			lon2:     -0.1278,
			expected: 5570,
			tolerance: 50,
		},
		{
			name:     "San Francisco to Tokyo",
			lat1:     37.7749,
			lon1:     -122.4194,
			lat2:     35.6762,
			lon2:     139.6503,
			expected: 8270,
			tolerance: 50,
		},
		{
			name:     "same location",
			lat1:     37.7749,
			lon1:     -122.4194,
			lat2:     37.7749,
			lon2:     -122.4194,
			expected: 0,
			tolerance: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			distance := haversineDistance(tt.lat1, tt.lon1, tt.lat2, tt.lon2)
			diff := distance - tt.expected
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.tolerance {
				t.Errorf("haversineDistance() = %v km, want %v ± %v km", distance, tt.expected, tt.tolerance)
			}
		})
	}
}

func TestCalculateDeviceScore(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// Test trusted device
	trustedFingerprint := DeviceFingerprint{
		Fingerprint: "trusted-fp-123",
		UserAgent:   "Mozilla/5.0",
		IPAddress:   "192.168.1.1",
		IsTrusted:   true,
		IsKnown:     true,
	}

	ctx := context.Background()
	score := scorer.CalculateDeviceScore(ctx, trustedFingerprint, "user123")
	if score != 0.0 {
		t.Errorf("Trusted device should have score 0, got %v", score)
	}

	// Test unknown device
	unknownFingerprint := DeviceFingerprint{
		Fingerprint: "unknown-fp-456",
		UserAgent:   "Mozilla/5.0",
		IPAddress:   "1.2.3.4",
		IsTrusted:   false,
		IsKnown:     false,
	}

	score = scorer.CalculateDeviceScore(ctx, unknownFingerprint, "user123")
	if score < 30 {
		t.Errorf("Unknown device should have score >= 30, got %v", score)
	}
}

func TestGetRecommendations(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	tests := []struct {
		level     RiskLevel
		factors   []RiskFactor
		checkFunc func([]string) bool
	}{
		{
			level: RiskLevelLow,
			factors: []RiskFactor{},
			checkFunc: func(actions []string) bool {
				for _, a := range actions {
					if a == "Allow normal authentication flow" {
						return true
					}
				}
				return false
			},
		},
		{
			level: RiskLevelMedium,
			factors: []RiskFactor{},
			checkFunc: func(actions []string) bool {
				hasMFA := false
				hasNotify := false
				for _, a := range actions {
					if a == "Require additional verification" {
						hasMFA = true
					}
					if a == "Notify user of unusual login" {
						hasNotify = true
					}
				}
				return hasMFA && hasNotify
			},
		},
		{
			level: RiskLevelHigh,
			factors: []RiskFactor{},
			checkFunc: func(actions []string) bool {
				hasStepUp := false
				hasLimitSession := false
				hasAlert := false
				for _, a := range actions {
					if a == "Require step-up authentication (MFA)" {
						hasStepUp = true
					}
					if a == "Limit session duration" {
						hasLimitSession = true
					}
					if a == "Send security alert to user" {
						hasAlert = true
					}
				}
				return hasStepUp && hasLimitSession && hasAlert
			},
		},
		{
			level: RiskLevelCritical,
			factors: []RiskFactor{
				{Name: "impossible_travel", Score: 100},
			},
			checkFunc: func(actions []string) bool {
				hasBlock := false
				hasAdmin := false
				hasLock := false
				for _, a := range actions {
					if a == "Block authentication attempt" {
						hasBlock = true
					}
					if a == "Require administrator approval" {
						hasAdmin = true
					}
					if a == "Temporarily lock account" {
						hasLock = true
					}
				}
				return hasBlock && hasAdmin && hasLock
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			actions := scorer.getRecommendations(tt.level, tt.factors)
			if !tt.checkFunc(actions) {
				t.Errorf("Test %d: Recommendations don't match expected for level %s", i, tt.level)
			}
		})
	}
}

func TestSetWeights(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	// Set custom weights
	scorer.SetWeights(0.3, 0.2, 0.15, 0.25, 0.1)

	// Check that weights are normalized (should sum to 1.0)
	total := scorer.IPReputationWeight +
	         scorer.DeviceScoreWeight +
	         scorer.GeolocationWeight +
	         scorer.LoginVelocityWeight +
	         scorer.ImpossibleTravelWeight

	if total < 0.99 || total > 1.01 {
		t.Errorf("Weights sum to %v, expected ~1.0", total)
	}
}

func TestSetThresholds(t *testing.T) {
	scorer := NewRiskScorer(nil, nil, zap.NewNop())

	scorer.SetThresholds(20, 40, 60)

	if scorer.LowRiskThreshold != 20 {
		t.Errorf("LowRiskThreshold = %v, want 20", scorer.LowRiskThreshold)
	}
	if scorer.MediumRiskThreshold != 40 {
		t.Errorf("MediumRiskThreshold = %v, want 40", scorer.MediumRiskThreshold)
	}
	if scorer.HighRiskThreshold != 60 {
		t.Errorf("HighRiskThreshold = %v, want 60", scorer.HighRiskThreshold)
	}

	// Test classification with new thresholds
	if scorer.classifyRiskLevel(15) != RiskLevelLow {
		t.Error("Score 15 should be Low with threshold 20")
	}
	if scorer.classifyRiskLevel(30) != RiskLevelMedium {
		t.Error("Score 30 should be Medium with thresholds 20/40")
	}
	if scorer.classifyRiskLevel(50) != RiskLevelHigh {
		t.Error("Score 50 should be High with thresholds 20/40/60")
	}
	if scorer.classifyRiskLevel(70) != RiskLevelCritical {
		t.Error("Score 70 should be Critical with threshold 60")
	}
}

func TestKmHelper(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected float64
	}{
		{time.Hour, 900},           // 900 km in 1 hour at 900 km/h
		{2 * time.Hour, 1800},      // 1800 km in 2 hours
		{30 * time.Minute, 450},    // 450 km in 30 minutes
	}

	for _, tt := range tests {
		t.Run(tt.duration.String(), func(t *testing.T) {
			km := tt.duration.Km()
			if km != tt.expected {
				t.Errorf("Km() = %v, want %v", km, tt.expected)
			}
		})
	}
}
