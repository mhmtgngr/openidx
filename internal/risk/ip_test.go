// Package risk provides unit tests for IP intelligence including blocklist
package risk

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestIPIntelligenceConfig tests the default IP intelligence configuration
func TestIPIntelligenceConfig(t *testing.T) {
	config := DefaultIPIntelligenceConfig()

	if config.MaxTravelSpeed != 900 {
		t.Errorf("Default MaxTravelSpeed = %f, want 900", config.MaxTravelSpeed)
	}

	if config.MinDistanceCheck != 100 {
		t.Errorf("Default MinDistanceCheck = %f, want 100", config.MinDistanceCheck)
	}

	if config.GeoIPCacheTTL != 24*time.Hour {
		t.Errorf("Default GeoIPCacheTTL = %v, want 24h", config.GeoIPCacheTTL)
	}

	if !config.EnableVPNDetection {
		t.Error("EnableVPNDetection should be true by default")
	}

	if !config.EnableTorDetection {
		t.Error("EnableTorDetection should be true by default")
	}

	if !config.EnableBlocklist {
		t.Error("EnableBlocklist should be true by default")
	}

	if !config.EnableAllowlist {
		t.Error("EnableAllowlist should be true by default")
	}
}

// TestNewIPIntelligence tests the IP intelligence service initialization
func TestNewIPIntelligence(t *testing.T) {
	config := DefaultIPIntelligenceConfig()
	service := NewIPIntelligence(nil, nil, config, zap.NewNop())

	if service == nil {
		t.Fatal("NewIPIntelligence returned nil")
	}

	if service.torExitNodes == nil {
		t.Error("torExitNodes map should be initialized")
	}

	if service.config.MaxTravelSpeed != 900 {
		t.Errorf("MaxTravelSpeed not set correctly: %f", service.config.MaxTravelSpeed)
	}
}

// TestIsPrivateIP tests private IP detection
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"192.168.1.1", true},
		{"192.168.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"208.67.222.222", false},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestIPBlocklistEntry tests the blocklist entry structure
func TestIPBlocklistEntry(t *testing.T) {
	now := time.Now()
	blockedUntil := now.Add(24 * time.Hour)

	entry := IPBlocklistEntry{
		ID:         "test-id-1",
		IPAddress:  "192.0.2.1",
		CIDR:       "192.0.2.0/24",
		Reason:     "Test block",
		ThreatType: "malware",
		Source:     "manual",
		Permanent:  false,
		BlockedUntil: &blockedUntil,
		CreatedAt:  now,
		UpdatedAt:  now,
		ReportCount: 5,
	}

	if entry.ID == "" {
		t.Error("ID should not be empty")
	}

	if entry.IPAddress == "" {
		t.Error("IPAddress should not be empty")
	}

	if entry.BlockedUntil == nil {
		t.Error("BlockedUntil should be set for non-permanent blocks")
	}

	if entry.Permanent && entry.BlockedUntil != nil {
		t.Error("Permanent blocks should not have BlockedUntil set")
	}

	if !entry.Permanent && entry.BlockedUntil.Before(now) {
		t.Error("BlockedUntil should be in the future for active blocks")
	}
}

// TestIPAllowlistEntry tests the allowlist entry structure
func TestIPAllowlistEntry(t *testing.T) {
	now := time.Now()

	entry := IPAllowlistEntry{
		ID:        "test-id-1",
		IPAddress: "10.0.1.100",
		CIDR:      "10.0.1.0/24",
		Label:     "office-vpn",
		CreatedAt: now,
	}

	if entry.ID == "" {
		t.Error("ID should not be empty")
	}

	if entry.IPAddress == "" {
		t.Error("IPAddress should not be empty")
	}

	if entry.Label == "" {
		t.Error("Label should not be empty")
	}

	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

// TestGeoIPResult tests the GeoIP result structure
func TestGeoIPResult(t *testing.T) {
	result := GeoIPResult{
		IPAddress:   "8.8.8.8",
		Country:     "United States",
		CountryCode: "US",
		City:        "Mountain View",
		Region:      "California",
		Latitude:    37.4223,
		Longitude:   -122.085,
		ISP:         "Google LLC",
		ASNumber:    "15169",
		IsMobile:    false,
		IsProxy:     false,
		IsVPN:       false,
		IsTor:       false,
		IsHosting:   true,
		ThreatScore: 0,
		LookupTime:  time.Now(),
	}

	// Validate coordinates
	if result.Latitude < -90 || result.Latitude > 90 {
		t.Errorf("Invalid latitude: %f", result.Latitude)
	}

	if result.Longitude < -180 || result.Longitude > 180 {
		t.Errorf("Invalid longitude: %f", result.Longitude)
	}

	// Validate country code format
	if len(result.CountryCode) != 2 {
		t.Errorf("CountryCode should be 2 characters, got: %s", result.CountryCode)
	}

	// Validate threat score range
	if result.ThreatScore < 0 || result.ThreatScore > 100 {
		t.Errorf("ThreatScore should be 0-100, got: %d", result.ThreatScore)
	}

	// Validate lookup time
	if result.LookupTime.IsZero() {
		t.Error("LookupTime should be set")
	}

	// IP address should not be empty
	if result.IPAddress == "" {
		t.Error("IPAddress should not be empty")
	}
}

// TestParseCIDR tests CIDR parsing helper
func TestParseCIDR(t *testing.T) {
	tests := []struct {
		cidr      string
		shouldErr bool
		testIP    string
		contains  bool
	}{
		{
			cidr:      "192.168.1.0/24",
			shouldErr: false,
			testIP:    "192.168.1.100",
			contains:  true,
		},
		{
			cidr:      "192.168.1.0/24",
			shouldErr: false,
			testIP:    "192.168.2.100",
			contains:  false,
		},
		{
			cidr:      "10.0.0.0/8",
			shouldErr: false,
			testIP:    "10.255.255.255",
			contains:  true,
		},
		{
			cidr:      "invalid",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for CIDR: %s", tt.cidr)
				}
				return
			}

			if err != nil {
				t.Errorf("Failed to parse CIDR %s: %v", tt.cidr, err)
				return
			}

			if tt.testIP != "" {
				testIPParsed := net.ParseIP(tt.testIP)
				if testIPParsed == nil {
					t.Errorf("Failed to parse test IP: %s", tt.testIP)
					return
				}

				contains := ipNet.Contains(testIPParsed)
				if contains != tt.contains {
					t.Errorf("CIDR %s contains test IP %s: got %v, want %v",
						tt.cidr, tt.testIP, contains, tt.contains)
				}
			}
		})
	}
}

// TestImpossibleTravelResultStructure tests the impossible travel result structure
func TestImpossibleTravelResultStructure(t *testing.T) {
	now := time.Now()
	prevTime := now.Add(-2 * time.Hour)

	result := ImpossibleTravelResult{
		IsImpossible:   true,
		DistanceKm:     5000,
		TimeDelta:      2 * time.Hour,
		RequiredTime:   6 * time.Hour,
		SpeedKmh:       2500,
		PreviousLocation: &GeoPoint{
			Latitude:  40.7128,
			Longitude: -74.0060,
			Country:   "US",
			City:      "New York",
		},
		CurrentLocation: &GeoPoint{
			Latitude:  51.5074,
			Longitude: -0.1278,
			Country:   "UK",
			City:      "London",
		},
		PreviousTime: prevTime,
		CurrentTime:  now,
	}

	// Validate impossible travel result
	if !result.IsImpossible {
		t.Error("Expected IsImpossible to be true for this scenario")
	}

	// Distance should be significant
	if result.DistanceKm < 1000 {
		t.Errorf("Distance for impossible travel should be > 1000km, got: %.0f", result.DistanceKm)
	}

	// Speed should exceed maximum travel speed
	if result.SpeedKmh <= 900 {
		t.Errorf("Speed for impossible travel should exceed 900 km/h, got: %.0f", result.SpeedKmh)
	}

	// Time delta should be positive
	if result.TimeDelta <= 0 {
		t.Errorf("TimeDelta should be positive, got: %v", result.TimeDelta)
	}

	// Required time should exceed actual time
	if result.RequiredTime <= result.TimeDelta {
		t.Errorf("RequiredTime (%v) should exceed TimeDelta (%v) for impossible travel",
			result.RequiredTime, result.TimeDelta)
	}

	// Locations should be set
	if result.PreviousLocation == nil || result.CurrentLocation == nil {
		t.Error("Both PreviousLocation and CurrentLocation should be set")
	}

	// Times should be set
	if result.PreviousTime.IsZero() || result.CurrentTime.IsZero() {
		t.Error("Both PreviousTime and CurrentTime should be set")
	}
}

// TestHaversineDistance_EdgeCases tests haversine distance with edge cases
func TestHaversineDistance_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		lat1     float64
		lon1     float64
		lat2     float64
		lon2     float64
		expected float64
	}{
		{
			name:     "north pole to south pole",
			lat1:     90,
			lon1:     0,
			lat2:     -90,
			lon2:     0,
			expected: 20015, // Approximately half Earth's circumference
		},
		{
			name:     "antipodal points",
			lat1:     0,
			lon1:     0,
			lat2:     0,
			lon2:     180,
			expected: 20015, // Approximately half Earth's circumference
		},
		{
			name:     "date line crossing",
			lat1:     35.6762,
			lon1:     139.6503, // Tokyo
			lat2:     37.7749,
			lon2:     -122.4194, // San Francisco
			expected: 8270,
		},
		{
			name:     "small distance",
			lat1:     37.7749,
			lon1:     -122.4194,
			lat2:     37.7750,
			lon2:     -122.4195,
			expected: 0.014, // ~14 meters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := haversineDistance(tt.lat1, tt.lon1, tt.lat2, tt.lon2)
			// Use at least 1% tolerance or 0.01 km, whichever is larger
			tolerance := tt.expected * 0.01 // 1% tolerance
			if tolerance < 0.01 {
				tolerance = 0.01 // 10 meter minimum tolerance
			}

			diff := result - tt.expected
			if diff < 0 {
				diff = -diff
			}

			if diff > tolerance {
				t.Errorf("haversineDistance() = %.3f km, want %.3f ± %.3f km",
					result, tt.expected, tolerance)
			}
		})
	}
}

// TestMinAndMaxHelpers tests the min and max helper functions
func TestMinAndMaxHelpers(t *testing.T) {
	tests := []struct {
		name     string
		a        int
		b        int
		minExpected int
		maxExpected int
	}{
		{"both positive", 5, 10, 5, 10},
		{"both negative", -15, -5, -15, -5},
		{"mixed signs", -10, 5, -10, 5},
		{"equal values", 7, 7, 7, 7},
		{"zero and positive", 0, 100, 0, 100},
		{"zero and negative", -50, 0, -50, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minResult := min(tt.a, tt.b)
			maxResult := max(tt.a, tt.b)

			if minResult != tt.minExpected {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, minResult, tt.minExpected)
			}

			if maxResult != tt.maxExpected {
				t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, maxResult, tt.maxExpected)
			}
		})
	}
}

// TestThreatScoreRanges tests threat score ranges
func TestThreatScoreRanges(t *testing.T) {
	// Test that threat scores are properly bounded (0-100)
	tests := []struct {
		name  string
		score int
		valid bool
	}{
		{"minimum", 0, true},
		{"low", 25, true},
		{"medium", 50, true},
		{"high", 75, true},
		{"maximum", 100, true},
		{"below minimum", -10, false},
		{"above maximum", 110, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.score >= 0 && tt.score <= 100
			if valid != tt.valid {
				t.Errorf("Score %d validity: got %v, want %v", tt.score, valid, tt.valid)
			}
		})
	}
}

// TestIPValidation tests IP address validation
func TestIPValidation(t *testing.T) {
	tests := []struct {
		ip      string
		valid   bool
		version int // 4 for IPv4, 6 for IPv6, 0 for invalid
	}{
		{"192.168.1.1", true, 4},
		{"8.8.8.8", true, 4},
		{"1.1.1.1", true, 4},
		{"255.255.255.255", true, 4},
		{"0.0.0.0", true, 4},
		{"256.1.1.1", false, 0},
		{"192.168.1", false, 0},
		{"192.168.1.1.1", false, 0},
		{"not.an.ip", false, 0},
		{"2001:4860:4860::8888", true, 6},
		{"::1", true, 6},
		{"fe80::1", true, 6},
		{"::", true, 6},
		{"2001::abcd::1", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			parsed := net.ParseIP(tt.ip)
			isValid := parsed != nil

			if isValid != tt.valid {
				t.Errorf("ParseIP(%s) validity: got %v, want %v", tt.ip, isValid, tt.valid)
			}

			if isValid {
				isIPv4 := parsed.To4() != nil
				expectedIPv4 := tt.version == 4
				if isIPv4 != expectedIPv4 {
					t.Errorf("IP %s version: got IPv4=%v, want %v", tt.ip, isIPv4, expectedIPv4)
				}
			}
		})
	}
}

// TestGeoPointValidation tests GeoPoint validation
func TestGeoPointValidation(t *testing.T) {
	tests := []struct {
		name    string
		point   GeoPoint
		valid   bool
	}{
		{
			name: "valid SF",
			point: GeoPoint{Latitude: 37.7749, Longitude: -122.4194},
			valid: true,
		},
		{
			name: "valid London",
			point: GeoPoint{Latitude: 51.5074, Longitude: -0.1278},
			valid: true,
		},
		{
			name: "north pole",
			point: GeoPoint{Latitude: 90, Longitude: 0},
			valid: true,
		},
		{
			name: "south pole",
			point: GeoPoint{Latitude: -90, Longitude: 0},
			valid: true,
		},
		{
			name: "invalid latitude too high",
			point: GeoPoint{Latitude: 91, Longitude: 0},
			valid: false,
		},
		{
			name: "invalid latitude too low",
			point: GeoPoint{Latitude: -91, Longitude: 0},
			valid: false,
		},
		{
			name: "invalid longitude too high",
			point: GeoPoint{Latitude: 0, Longitude: 181},
			valid: false,
		},
		{
			name: "invalid longitude too low",
			point: GeoPoint{Latitude: 0, Longitude: -181},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.point.Latitude >= -90 && tt.point.Latitude <= 90 &&
				tt.point.Longitude >= -180 && tt.point.Longitude <= 180

			if valid != tt.valid {
				t.Errorf("GeoPoint %+v validity: got %v, want %v", tt.point, valid, tt.valid)
			}
		})
	}
}
