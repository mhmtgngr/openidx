// Package risk provides unit tests for behavioral analytics
package risk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TestBehaviorTracker_TrackLogin tests login tracking functionality
func TestBehaviorTracker_TrackLogin(t *testing.T) {
	// Setup miniredis for testing
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, redisClient, config, zap.NewNop())

	ctx := context.Background()
	userID := "user123"
	ip := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
	lat := 40.7128
	lon := -74.0060
	loginTime := time.Now().UTC()

	// Track a login
	err := tracker.TrackLogin(ctx, userID, ip, userAgent, lat, lon, loginTime)
	if err != nil {
		t.Fatalf("TrackLogin failed: %v", err)
	}

	// Verify the login hour was tracked
	hourKey := "behavior:user:user123:hours"
	hour := loginTime.Hour()
	member := fmt.Sprintf("hour:%d", hour) // "hour:N"

	score := client.ZScore(ctx, hourKey, member).Val()
	if score != 1 {
		t.Errorf("Expected hour score to be 1, got %f", score)
	}

	// Track another login at the same hour
	err = tracker.TrackLogin(ctx, userID, ip, userAgent, lat, lon, loginTime)
	if err != nil {
		t.Fatalf("TrackLogin failed: %v", err)
	}

	score = client.ZScore(ctx, hourKey, member).Val()
	if score != 2 {
		t.Errorf("Expected hour score to be 2, got %f", score)
	}
}

// TestBehaviorTracker_GetBehaviorProfile tests behavior profile retrieval
func TestBehaviorTracker_GetBehaviorProfile(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, redisClient, config, zap.NewNop())

	ctx := context.Background()
	userID := "user456"

	// Track multiple logins to build profile
	loginTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC) // 9 AM
	for i := 0; i < 10; i++ {
		err := tracker.TrackLogin(ctx, userID, "192.168.1.1", "Chrome", 40.7128, -74.0060, loginTime)
		if err != nil {
			t.Fatalf("TrackLogin failed: %v", err)
		}
	}

	// Get the profile
	profile, err := tracker.GetBehaviorProfile(ctx, userID)
	if err != nil {
		t.Fatalf("GetBehaviorProfile failed: %v", err)
	}

	// Verify profile data
	if profile.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, profile.UserID)
	}

	if profile.LoginCount != 10 {
		t.Errorf("Expected LoginCount 10, got %d", profile.LoginCount)
	}

	if !profile.ProfileEstablished {
		t.Error("Profile should be established with 10 logins")
	}

	if len(profile.TypicalLocations) == 0 {
		t.Error("Expected at least one typical location")
	}

	if len(profile.TypicalDevices) == 0 {
		t.Error("Expected at least one typical device")
	}
}

// TestBehaviorTracker_DetectAnomalies tests anomaly detection
func TestBehaviorTracker_DetectAnomalies(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := BehaviorConfig{
		MinLoginsForProfile:  5,
		StdDevThreshold:      2.0,
		LocationThresholdKm:  500,
		MaxLocations:         10,
		MaxDevices:           5,
		MaxResources:         20,
	}
	tracker := NewBehaviorTracker(nil, redisClient, config, zap.NewNop())

	ctx := context.Background()
	userID := "user789"

	// Establish baseline with logins at 9 AM with some variance
	// (8 AM, 9 AM, 10 AM) to create a standard deviation > 0
	for i := 0; i < 10; i++ {
		hour := 9
		switch i % 3 {
		case 0:
			hour = 8
		case 1:
			hour = 10
		}
		loginTime := time.Date(2024, 1, 1, hour, 0, 0, 0, time.UTC)
		err := tracker.TrackLogin(ctx, userID, "192.168.1.1", "Chrome", 40.7128, -74.0060, loginTime)
		if err != nil {
			t.Fatalf("TrackLogin failed: %v", err)
		}
	}

	tests := []struct {
		name          string
		hour          int
		lat           float64
		lon           float64
		ip            string
		userAgent     string
		expectAnomaly bool
		minRiskScore  int
	}{
		{
			name:          "normal login - same hour and location",
			hour:          9,
			lat:           40.7128,
			lon:           -74.0060,
			ip:            "192.168.1.1",
			userAgent:     "Chrome", // Use same as baseline
			expectAnomaly: false,
			minRiskScore:  0,
		},
		{
			name:          "unusual hour - 3 AM",
			hour:          3,
			lat:           40.7128,
			lon:           -74.0060,
			ip:            "192.168.1.1",
			userAgent:     "Chrome",
			expectAnomaly: true,
			minRiskScore:  25, // Unusual hour penalty
		},
		{
			name:          "new location - far away",
			hour:          9,
			lat:           51.5074,  // London
			lon:           -0.1278,
			ip:            "192.168.1.1",
			userAgent:     "Chrome",
			expectAnomaly: true,
			minRiskScore:  30, // New location penalty
		},
		{
			name:          "new device",
			hour:          9,
			lat:           40.7128,
			lon:           -74.0060,
			ip:            "10.0.0.1",
			userAgent:     "Firefox",
			expectAnomaly: true,
			minRiskScore:  20, // New device penalty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginTime := time.Date(2024, 1, 1, tt.hour, 0, 0, 0, time.UTC)

			anomalies, riskScore := tracker.DetectAnomalies(
				ctx,
				userID,
				tt.ip,
				tt.userAgent,
				tt.lat,
				tt.lon,
				loginTime,
			)

			if tt.expectAnomaly && len(anomalies) == 0 {
				t.Errorf("Expected anomalies but got none")
			}

			if !tt.expectAnomaly && len(anomalies) > 0 {
				t.Errorf("Expected no anomalies but got: %v", anomalies)
			}

			if riskScore < tt.minRiskScore {
				t.Errorf("Expected risk score >= %d, got %d", tt.minRiskScore, riskScore)
			}
		})
	}
}

// TestBehaviorTracker_isAnomalousHour tests the anomalous hour detection
func TestBehaviorTracker_isAnomalousHour(t *testing.T) {
	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, nil, config, zap.NewNop())

	tests := []struct {
		name       string
		hour       int
		mean       float64
		stdDev     float64
		isAnomalous bool
	}{
		{
			name:       "within 1 std dev",
			hour:       10,
			mean:       9,
			stdDev:     2,
			isAnomalous: false, // |10-9|/2 = 0.5 < 2
		},
		{
			name:       "within 2 std dev",
			hour:       13,
			mean:       9,
			stdDev:     2,
			isAnomalous: false, // |13-9|/2 = 2.0, not > 2
		},
		{
			name:       "beyond 2 std dev",
			hour:       14,
			mean:       9,
			stdDev:     2,
			isAnomalous: true, // |14-9|/2 = 2.5 > 2
		},
		{
			name:       "zero std dev - no variance",
			hour:       10,
			mean:       9,
			stdDev:     0,
			isAnomalous: false, // Should return false when stdDev is 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracker.isAnomalousHour(tt.hour, tt.mean, tt.stdDev)
			if result != tt.isAnomalous {
				t.Errorf("isAnomalousHour(%d, %.1f, %.1f) = %v, want %v",
					tt.hour, tt.mean, tt.stdDev, result, tt.isAnomalous)
			}
		})
	}
}

// TestBehaviorTracker_isNewLocation tests new location detection
func TestBehaviorTracker_isNewLocation(t *testing.T) {
	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, nil, config, zap.NewNop())

	knownLocations := []GeoPoint{
		{Latitude: 40.7128, Longitude: -74.0060}, // New York
		{Latitude: 34.0522, Longitude: -118.2437}, // Los Angeles
		{Latitude: 51.5074, Longitude: -0.1278},   // London
	}

	tests := []struct {
		name          string
		lat           float64
		lon           float64
		expectNew     bool
		minDistance   float64
	}{
		{
			name:        "same as known location",
			lat:         40.7128,
			lon:         -74.0060,
			expectNew:   false,
			minDistance: 0,
		},
		{
			name:        "near known location",
			lat:         40.73,
			lon:         -73.99,
			expectNew:   false,
			minDistance: 2, // ~2km from NYC
		},
		{
			name:        "far from known locations",
			lat:         35.6762,
			lon:         139.6503, // Tokyo
			expectNew:   true,
			minDistance: 8800, // ~8800km from NYC
		},
		{
			name:        "just beyond threshold",
			lat:         39.0,
			lon:         -75.0, // ~200km from NYC
			expectNew:   false,
			minDistance: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isNew, distance := tracker.isNewLocation(tt.lat, tt.lon, knownLocations)

			if isNew != tt.expectNew {
				t.Errorf("isNewLocation(%.4f, %.4f) = %v, want %v",
					tt.lat, tt.lon, isNew, tt.expectNew)
			}

			if distance < tt.minDistance-10 { // Allow small variance
				t.Errorf("Expected distance >= %.0fkm, got %.0fkm",
					tt.minDistance, distance)
			}
		})
	}
}

// TestBehaviorTracker_computeDeviceFingerprint tests device fingerprint computation
func TestBehaviorTracker_computeDeviceFingerprint(t *testing.T) {
	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, nil, config, zap.NewNop())

	tests := []struct {
		name        string
		ip          string
		userAgent   string
		expectMatch bool // Whether two calls should match
	}{
		{
			name:        "same IP and user agent",
			ip:          "192.168.1.100",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			expectMatch: true,
		},
		{
			name:        "same /24 subnet",
			ip:          "192.168.1.1",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			expectMatch: true,
		},
		{
			name:        "different /24 subnet",
			ip:          "192.168.2.1",
			userAgent:   "Chrome",
			expectMatch: false,
		},
		{
			name:        "different user agent",
			ip:          "192.168.1.1",
			userAgent:   "Firefox",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp1 := tracker.computeDeviceFingerprint(tt.ip, tt.userAgent)
			fp2 := tracker.computeDeviceFingerprint("192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

			if tt.expectMatch && fp1 != fp2 {
				t.Errorf("Expected matching fingerprints for same subnet/useragent: %s != %s", fp1, fp2)
			}

			if !tt.expectMatch && fp1 == fp2 {
				t.Errorf("Expected different fingerprints for different IP/UA: %s == %s", fp1, fp2)
			}
		})
	}
}

// TestBehaviorTracker_ClearBehaviorProfile tests profile clearing
func TestBehaviorTracker_ClearBehaviorProfile(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, redisClient, config, zap.NewNop())

	ctx := context.Background()
	userID := "user999"

	// Track some logins
	loginTime := time.Now().UTC()
	err := tracker.TrackLogin(ctx, userID, "192.168.1.1", "Chrome", 40.7128, -74.0060, loginTime)
	if err != nil {
		t.Fatalf("TrackLogin failed: %v", err)
	}

	// Verify data exists
	profile, _ := tracker.GetBehaviorProfile(ctx, userID)
	if profile.LoginCount == 0 {
		t.Error("Expected login count > 0 before clearing")
	}

	// Clear the profile
	err = tracker.ClearBehaviorProfile(ctx, userID)
	if err != nil {
		t.Fatalf("ClearBehaviorProfile failed: %v", err)
	}

	// Verify data is cleared
	profile, _ = tracker.GetBehaviorProfile(ctx, userID)
	if profile.LoginCount != 0 {
		t.Errorf("Expected login count 0 after clearing, got %d", profile.LoginCount)
	}
}

// TestBehaviorTracker_GetUserBehaviorSummary tests behavior summary generation
func TestBehaviorTracker_GetUserBehaviorSummary(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultBehaviorConfig()
	tracker := NewBehaviorTracker(nil, redisClient, config, zap.NewNop())

	ctx := context.Background()
	userID := "user888"

	// Track some logins
	loginTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ { // Use 4 logins, below the threshold of 5
		err := tracker.TrackLogin(ctx, userID, "192.168.1.1", "Chrome", 40.7128, -74.0060, loginTime)
		if err != nil {
			t.Fatalf("TrackLogin failed: %v", err)
		}
	}

	// Get summary
	summary, err := tracker.GetUserBehaviorSummary(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserBehaviorSummary failed: %v", err)
	}

	// Verify summary fields
	if summary["user_id"] != userID {
		t.Errorf("Expected user_id %s, got %v", userID, summary["user_id"])
	}

	if summary["login_count"].(int) != 4 {
		t.Errorf("Expected login_count 4, got %v", summary["login_count"])
	}

	if summary["profile_established"].(bool) {
		t.Error("Profile should not be established with only 4 logins (threshold is 5)")
	}

	if summary["location_count"].(int) == 0 {
		t.Error("Expected at least 1 location")
	}

	if summary["device_count"].(int) == 0 {
		t.Error("Expected at least 1 device")
	}
}

// TestBehaviorConfig tests the behavior configuration defaults
func TestBehaviorConfig(t *testing.T) {
	config := DefaultBehaviorConfig()

	if config.MinLoginsForProfile != 5 {
		t.Errorf("Expected MinLoginsForProfile 5, got %d", config.MinLoginsForProfile)
	}

	if config.StdDevThreshold != 2.0 {
		t.Errorf("Expected StdDevThreshold 2.0, got %f", config.StdDevThreshold)
	}

	if config.LocationThresholdKm != 500 {
		t.Errorf("Expected LocationThresholdKm 500, got %f", config.LocationThresholdKm)
	}

	if config.MaxLocations != 10 {
		t.Errorf("Expected MaxLocations 10, got %d", config.MaxLocations)
	}

	if config.MaxDevices != 5 {
		t.Errorf("Expected MaxDevices 5, got %d", config.MaxDevices)
	}

	if config.MaxResources != 20 {
		t.Errorf("Expected MaxResources 20, got %d", config.MaxResources)
	}
}

// TestHaversineDistance tests the haversine distance calculation
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
			name:     "NYC to London",
			lat1:     40.7128,
			lon1:     -74.0060,
			lat2:     51.5074,
			lon2:     -0.1278,
			expected: 5570,
			tolerance: 50,
		},
		{
			name:     "NYC to LA",
			lat1:     40.7128,
			lon1:     -74.0060,
			lat2:     34.0522,
			lon2:     -118.2437,
			expected: 3944,
			tolerance: 50,
		},
		{
			name:     "same location",
			lat1:     40.7128,
			lon1:     -74.0060,
			lat2:     40.7128,
			lon2:     -74.0060,
			expected: 0,
			tolerance: 1,
		},
		{
			name:     "short distance",
			lat1:     40.7128,
			lon1:     -74.0060,
			lat2:     40.73,
			lon2:     -73.99,
			expected: 2,
			tolerance: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			distance := haversineDistance(tt.lat1, tt.lon1, tt.lat2, tt.lon2)

			if distance < tt.expected-tt.tolerance || distance > tt.expected+tt.tolerance {
				t.Errorf("haversineDistance() = %.0fkm, want %.0fkm ±%.0fkm",
					distance, tt.expected, tt.tolerance)
			}
		})
	}
}

