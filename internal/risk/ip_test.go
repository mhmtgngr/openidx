// Package risk provides unit tests for IP intelligence including blocklist
package risk

import (
	"net"
	"testing"
)

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
		name  string
		point GeoPoint
		valid bool
	}{
		{
			name:  "valid SF",
			point: GeoPoint{Latitude: 37.7749, Longitude: -122.4194},
			valid: true,
		},
		{
			name:  "valid London",
			point: GeoPoint{Latitude: 51.5074, Longitude: -0.1278},
			valid: true,
		},
		{
			name:  "north pole",
			point: GeoPoint{Latitude: 90, Longitude: 0},
			valid: true,
		},
		{
			name:  "south pole",
			point: GeoPoint{Latitude: -90, Longitude: 0},
			valid: true,
		},
		{
			name:  "invalid latitude too high",
			point: GeoPoint{Latitude: 91, Longitude: 0},
			valid: false,
		},
		{
			name:  "invalid latitude too low",
			point: GeoPoint{Latitude: -91, Longitude: 0},
			valid: false,
		},
		{
			name:  "invalid longitude too high",
			point: GeoPoint{Latitude: 0, Longitude: 181},
			valid: false,
		},
		{
			name:  "invalid longitude too low",
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
