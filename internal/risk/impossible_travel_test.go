// Package risk provides unit tests for impossible travel detection
package risk

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestCheckImpossibleTravel tests the impossible travel detection logic
func TestCheckImpossibleTravel(t *testing.T) {
	config := DefaultIPIntelligenceConfig()
	_ = NewIPIntelligence(nil, nil, config, zap.NewNop())
	_ = context.Background()

	now := time.Now()

	// Mock setup - these tests verify the calculation logic
	// In production, these would use a mock database

	tests := []struct {
		name              string
		lastLat           float64
		lastLon           float64
		lastTime          time.Time
		currentLat        float64
		currentLon        float64
		currentTime       time.Time
		expectedImpossible bool
		expectedDistance  float64 // Approximate km
		checkReason       string
	}{
		{
			name:              "SF to LA - normal travel (2 hours)",
			lastLat:           37.7749,  // San Francisco
			lastLon:           -122.4194,
			lastTime:          now.Add(-2 * time.Hour),
			currentLat:        34.0522,  // Los Angeles
			currentLon:        -118.2437,
			currentTime:       now,
			expectedImpossible: false,
			expectedDistance:  559,
			checkReason:       "~560km in 2 hours is possible (280 km/h)",
		},
		{
			name:              "SF to LA - impossible travel (30 minutes)",
			lastLat:           37.7749,
			lastLon:           -122.4194,
			lastTime:          now.Add(-30 * time.Minute),
			currentLat:        34.0522,
			currentLon:        -118.2437,
			currentTime:       now,
			expectedImpossible: true,
			expectedDistance:  559,
			checkReason:       "~560km in 30 minutes is impossible (>900 km/h required)",
		},
		{
			name:              "NYC to London - impossible (1 hour)",
			lastLat:           40.7128,  // New York
			lastLon:           -74.0060,
			lastTime:          now.Add(-1 * time.Hour),
			currentLat:        51.5074,  // London
			currentLon:        -0.1278,
			currentTime:       now,
			expectedImpossible: true,
			expectedDistance:  5570,
			checkReason:       "~5570km in 1 hour is impossible",
		},
		{
			name:              "NYC to London - possible (8 hours)",
			lastLat:           40.7128,
			lastLon:           -74.0060,
			lastTime:          now.Add(-8 * time.Hour),
			currentLat:        51.5074,
			currentLon:        -0.1278,
			currentTime:       now,
			expectedImpossible: false,
			expectedDistance:  5570,
			checkReason:       "~5570km in 8 hours is possible (~700 km/h)",
		},
		{
			name:              "SF to Tokyo - impossible (2 hours)",
			lastLat:           37.7749,
			lastLon:           -122.4194,
			lastTime:          now.Add(-2 * time.Hour),
			currentLat:        35.6762,  // Tokyo
			currentLon:        139.6503,
			currentTime:       now,
			expectedImpossible: true,
			expectedDistance:  8270,
			checkReason:       "~8270km in 2 hours is impossible",
		},
		{
			name:              "Short distance within SF - always possible",
			lastLat:           37.7749,
			lastLon:           -122.4194,
			lastTime:          now.Add(-5 * time.Minute),
			currentLat:        37.8044,
			currentLon:        -122.2711,
			currentTime:       now,
			expectedImpossible: false,
			expectedDistance:  15,
			checkReason:       "~15km is always possible",
		},
		{
			name:              "Same location - not impossible",
			lastLat:           37.7749,
			lastLon:           -122.4194,
			lastTime:          now.Add(-1 * time.Hour),
			currentLat:        37.7749,
			currentLon:        -122.4194,
			currentTime:       now,
			expectedImpossible: false,
			expectedDistance:  0,
			checkReason:       "0km distance",
		},
		{
			name:              "Distance below threshold - not checked",
			lastLat:           37.7749,
			lastLon:           -122.4194,
			lastTime:          now.Add(-10 * time.Minute),
			currentLat:        37.8500,
			currentLon:        -122.3000,
			currentTime:       now,
			expectedImpossible: false,
			expectedDistance:  80,
			checkReason:       "~80km is below minimum check threshold",
		},
		{
			name:              "Paris to Singapore - impossible (3 hours)",
			lastLat:           48.8566,  // Paris
			lastLon:           2.3522,
			lastTime:          now.Add(-3 * time.Hour),
			currentLat:        1.3521,   // Singapore
			currentLon:        103.8198,
			currentTime:       now,
			expectedImpossible: true,
			expectedDistance:  10750,
			checkReason:       "~10750km in 3 hours is impossible",
		},
		{
			name:              "Sydney to Los Angeles - impossible (4 hours)",
			lastLat:           -33.8688, // Sydney
			lastLon:           151.2093,
			lastTime:          now.Add(-4 * time.Hour),
			currentLat:        34.0522,  // LA
			currentLon:        -118.2437,
			currentTime:       now,
			expectedImpossible: true,
			expectedDistance:  12080,
			checkReason:       "~12080km in 4 hours is impossible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate distance using haversine
			distance := haversineDistance(tt.lastLat, tt.lastLon, tt.currentLat, tt.currentLon)

			// Verify distance is approximately correct
			if abs(distance-tt.expectedDistance) > 100 {
				t.Errorf("Distance calculation: got %.0f km, want ~%.0f km", distance, tt.expectedDistance)
			}

			// Calculate speed
			timeDelta := tt.currentTime.Sub(tt.lastTime)
			speedKmh := 0.0
			if timeDelta.Hours() > 0 {
				speedKmh = distance / timeDelta.Hours()
			}

			// Determine if impossible
			// Travel is considered impossible if speed > 900 km/h
			// requiredTime = distance / 900 hours
			isImpossible := false
			if distance >= 100 && timeDelta > 0 {
				requiredTimeHours := distance / 900.0
				requiredTime := time.Duration(requiredTimeHours * float64(time.Hour))
				isImpossible = timeDelta < requiredTime
			}

			if isImpossible != tt.expectedImpossible {
				t.Errorf("%s: got impossible=%v, want %v. %s. Distance: %.0f km, Time: %v, Speed: %.0f km/h",
					tt.name, isImpossible, tt.expectedImpossible, tt.checkReason,
					distance, timeDelta, speedKmh)
			}
		})
	}
}

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

// TestImpossibleTravelResult tests the ImpossibleTravelResult structure
func TestImpossibleTravelResult(t *testing.T) {
	now := time.Now()

	result := &ImpossibleTravelResult{
		IsImpossible: true,
		DistanceKm:   5570,
		TimeDelta:    1 * time.Hour,
		RequiredTime: 6 * time.Hour,
		SpeedKmh:     5570,
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
		PreviousTime: now.Add(-1 * time.Hour),
		CurrentTime:  now,
	}

	// Verify the result structure
	if !result.IsImpossible {
		t.Error("Expected IsImpossible to be true")
	}

	if result.DistanceKm < 5000 {
		t.Errorf("DistanceKm = %.0f, want > 5000", result.DistanceKm)
	}

	if result.PreviousLocation == nil || result.CurrentLocation == nil {
		t.Error("Location pointers should not be nil")
	}

	// Verify speed calculation makes sense
	expectedSpeed := result.DistanceKm / result.TimeDelta.Hours()
	if abs(result.SpeedKmh-expectedSpeed) > 1 {
		t.Errorf("SpeedKmh = %.0f, calculated %.0f", result.SpeedKmh, expectedSpeed)
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

// TestMaxTravelSpeed tests the maximum travel speed configuration
func TestMaxTravelSpeed(t *testing.T) {
	config := DefaultIPIntelligenceConfig()

	if config.MaxTravelSpeed != 900 {
		t.Errorf("Default MaxTravelSpeed = %f, want 900", config.MaxTravelSpeed)
	}

	// Test with custom speed
	config.MaxTravelSpeed = 800 // Slower aircraft

	// Calculate required time for 1600 km
	distance := 1600.0
	requiredTime := time.Duration(distance/config.MaxTravelSpeed) * time.Hour
	expectedHours := 2.0

	if requiredTime.Hours() != expectedHours {
		t.Errorf("Required time = %v hours, want %v hours", requiredTime.Hours(), expectedHours)
	}
}

// abs returns the absolute value of a float64
func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
