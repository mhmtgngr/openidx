// Package risk provides unit tests for impossible travel detection
package risk

import (
	"testing"
	"time"
)

// TestHaversineDistance_Accuracy tests the haversine distance calculation accuracy
func TestHaversineDistance_Accuracy(t *testing.T) {
	tests := []struct {
		name      string
		lat1      float64
		lon1      float64
		lat2      float64
		lon2      float64
		expected  float64 // Expected distance in km
		tolerance float64 // Acceptable error in km
	}{
		{
			name:      "San Francisco to Los Angeles",
			lat1:      37.7749,
			lon1:      -122.4194,
			lat2:      34.0522,
			lon2:      -118.2437,
			expected:  559,
			tolerance: 10,
		},
		{
			name:      "New York to London",
			lat1:      40.7128,
			lon1:      -74.0060,
			lat2:      51.5074,
			lon2:      -0.1278,
			expected:  5570,
			tolerance: 50,
		},
		{
			name:      "San Francisco to Tokyo",
			lat1:      37.7749,
			lon1:      -122.4194,
			lat2:      35.6762,
			lon2:      139.6503,
			expected:  8270,
			tolerance: 50,
		},
		{
			name:      "Same location",
			lat1:      37.7749,
			lon1:      -122.4194,
			lat2:      37.7749,
			lon2:      -122.4194,
			expected:  0,
			tolerance: 1,
		},
		{
			name:      "Equator test (0,0 to 0,90)",
			lat1:      0,
			lon1:      0,
			lat2:      0,
			lon2:      90,
			expected:  10008, // ~1/4 of Earth's circumference
			tolerance: 50,
		},
		{
			name:      "North Pole to Equator (0,0 to 90,0)",
			lat1:      0,
			lon1:      0,
			lat2:      90,
			lon2:      0,
			expected:  10007, // ~1/4 of Earth's circumference
			tolerance: 50,
		},
		{
			name:      "London to Sydney",
			lat1:      51.5074,
			lon1:      -0.1278,
			lat2:      -33.8688,
			lon2:      151.2093,
			expected:  16990,
			tolerance: 100,
		},
		{
			name:      "Small distance - within city",
			lat1:      37.7749,
			lon1:      -122.4194,
			lat2:      37.7849,
			lon2:      -122.4094,
			expected:  1.5,
			tolerance: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := haversineDistance(tt.lat1, tt.lon1, tt.lat2, tt.lon2)
			diff := abs(result - tt.expected)

			if diff > tt.tolerance {
				t.Errorf("haversineDistance() = %.0f km, want %.0f ± %.0f km (diff: %.0f)",
					result, tt.expected, tt.tolerance, diff)
			}
		})
	}
}

// TestGeoPoint tests the GeoPoint structure
func TestGeoPoint(t *testing.T) {
	point := GeoPoint{
		Latitude:  37.7749,
		Longitude: -122.4194,
		Country:   "US",
		City:      "San Francisco",
	}

	if point.Latitude < -90 || point.Latitude > 90 {
		t.Errorf("Invalid latitude: %f", point.Latitude)
	}

	if point.Longitude < -180 || point.Longitude > 180 {
		t.Errorf("Invalid longitude: %f", point.Longitude)
	}

	if point.Country == "" {
		t.Error("Country should not be empty")
	}
}

// TestCalculateSpeed_InvalidInput tests edge cases for speed calculation
func TestCalculateSpeed_InvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		distance    float64
		timeDelta   time.Duration
		expectedKmh float64
	}{
		{
			name:        "zero time delta",
			distance:    100,
			timeDelta:   0,
			expectedKmh: 0,
		},
		{
			name:        "negative time delta",
			distance:    100,
			timeDelta:   -1 * time.Hour,
			expectedKmh: 0,
		},
		{
			name:        "zero distance",
			distance:    0,
			timeDelta:   1 * time.Hour,
			expectedKmh: 0,
		},
		{
			name:        "very small time",
			distance:    100,
			timeDelta:   1 * time.Millisecond,
			expectedKmh: 360000000, // 100 km / 1ms = 360,000,000 km/h
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateSpeed(tt.distance, tt.timeDelta)
			if result != tt.expectedKmh {
				t.Errorf("calculateSpeed(%.0f, %v) = %f, want %f",
					tt.distance, tt.timeDelta, result, tt.expectedKmh)
			}
		})
	}
}

// abs returns the absolute value of a float64
func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
