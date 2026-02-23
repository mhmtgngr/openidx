// Package risk provides behavioral analytics for user risk assessment
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// Redis key prefixes for behavioral tracking
const (
	// User behavior profiles
	behaviorKeyPrefix      = "behavior:user:"
	loginHoursKey          = "behavior:hours:"
	locationKey            = "behavior:location:"
	deviceKey              = "behavior:device:"
	resourceKey            = "behavior:resource:"

	// TTL for behavior data
	behaviorTTL = 30 * 24 * time.Hour // 30 days
)

// BehaviorProfile represents a user's behavioral baseline
type BehaviorProfile struct {
	UserID              string      `json:"user_id"`
	TypicalLoginHours   []int       `json:"typical_login_hours"`   // Hour 0-23
	TypicalLocations    []GeoPoint  `json:"typical_locations"`      // Known lat/lon
	TypicalDevices      []string    `json:"typical_devices"`        // Device fingerprints
	TypicalResources    []string    `json:"typical_resources"`      // Resources accessed
	LoginCount          int         `json:"login_count"`
	AverageLoginHour    float64     `json:"average_login_hour"`
	LoginHourStdDev     float64     `json:"login_hour_std_dev"`
	LastLoginTime       time.Time   `json:"last_login_time"`
	ProfileEstablished   bool        `json:"profile_established"`   // True if enough data collected
}

// GeoPoint represents a geographic location
type GeoPoint struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country,omitempty"`
	City      string  `json:"city,omitempty"`
}

// BehaviorConfig holds configuration for behavioral analytics
type BehaviorConfig struct {
	// Minimum logins before considering profile established
	MinLoginsForProfile int

	// Standard deviation threshold for anomalous hour detection
	StdDevThreshold float64

	// Distance threshold in km for new location detection
	LocationThresholdKm float64

	// Number of recent locations to track
	MaxLocations int

	// Number of recent devices to track
	MaxDevices int

	// Number of recent resources to track
	MaxResources int
}

// DefaultBehaviorConfig returns default behavioral analytics configuration
func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{
		MinLoginsForProfile:  5,
		StdDevThreshold:      2.0, // 2 standard deviations
		LocationThresholdKm:  500,
		MaxLocations:         10,
		MaxDevices:           5,
		MaxResources:         20,
	}
}

// BehaviorTracker handles behavioral analytics operations
type BehaviorTracker struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config BehaviorConfig
	logger *zap.Logger
}

// NewBehaviorTracker creates a new behavior tracker
func NewBehaviorTracker(db *database.PostgresDB, redis *database.RedisClient, config BehaviorConfig, logger *zap.Logger) *BehaviorTracker {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.MinLoginsForProfile == 0 {
		config = DefaultBehaviorConfig()
	}
	return &BehaviorTracker{
		db:     db,
		redis:  redis,
		config: config,
		logger: logger.With(zap.String("component", "behavior_tracker")),
	}
}

// TrackLogin records a login event for behavioral analysis
func (b *BehaviorTracker) TrackLogin(ctx context.Context, userID, ip, userAgent string, lat, lon float64, loginTime time.Time) error {
	// Generate device fingerprint
	fingerprint := b.computeDeviceFingerprint(ip, userAgent)

	// Record login hour (0-23)
	hour := loginTime.UTC().Hour()
	hourKey := fmt.Sprintf("%s%s:hours", behaviorKeyPrefix, userID)

	// Use Redis sorted set to track login hours with scores as counts
	pipe := b.redis.Client.Pipeline()

	// Increment count for this hour
	pipe.ZIncrBy(ctx, hourKey, 1, fmt.Sprintf("hour:%d", hour))
	pipe.Expire(ctx, hourKey, behaviorTTL)

	// Track location if valid
	if lat != 0 || lon != 0 {
		locationKey := fmt.Sprintf("%s%s:locations", behaviorKeyPrefix, userID)
		locationData := GeoPoint{Latitude: lat, Longitude: lon}
		locationJSON, _ := json.Marshal(locationData)

		// Add to sorted set with timestamp as score (dedup by location)
		locationHash := fmt.Sprintf("%.4f,%.4f", lat, lon)
		pipe.ZAdd(ctx, locationKey, redis.Z{
			Score:  float64(time.Now().Unix()),
			Member: locationHash,
		})
		pipe.Expire(ctx, locationKey, behaviorTTL)

		// Store location details in a separate hash
		pipe.HSet(ctx, fmt.Sprintf("%s%s:location:details", behaviorKeyPrefix, userID), locationHash, locationJSON)
		pipe.Expire(ctx, fmt.Sprintf("%s%s:location:details", behaviorKeyPrefix, userID), behaviorTTL)
	}

	// Track device
	deviceKey := fmt.Sprintf("%s%s:devices", behaviorKeyPrefix, userID)
	pipe.ZAdd(ctx, deviceKey, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: fingerprint,
	})
	pipe.Expire(ctx, deviceKey, behaviorTTL)

	// Update last login time
	pipe.Set(ctx, fmt.Sprintf("%s%s:last_login", behaviorKeyPrefix, userID), loginTime.Format(time.RFC3339), behaviorTTL)

	// Increment login count
	countKey := fmt.Sprintf("%s%s:count", behaviorKeyPrefix, userID)
	pipe.Incr(ctx, countKey)
	pipe.Expire(ctx, countKey, behaviorTTL)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to track login: %w", err)
	}

	return nil
}

// TrackResourceAccess records a resource access event
func (b *BehaviorTracker) TrackResourceAccess(ctx context.Context, userID, resourceURI string) error {
	resourceKey := fmt.Sprintf("%s%s:resources", behaviorKeyPrefix, userID)

	pipe := b.redis.Client.Pipeline()

	// Add to sorted set with timestamp as score
	pipe.ZAdd(ctx, resourceKey, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: resourceURI,
	})
	pipe.Expire(ctx, resourceKey, behaviorTTL)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to track resource access: %w", err)
	}

	return nil
}

// GetBehaviorProfile retrieves a user's behavior profile from Redis
func (b *BehaviorTracker) GetBehaviorProfile(ctx context.Context, userID string) (*BehaviorProfile, error) {
	profile := &BehaviorProfile{
		UserID: userID,
	}

	// Get login count
	countKey := fmt.Sprintf("%s%s:count", behaviorKeyPrefix, userID)
	count, err := b.redis.Client.Get(ctx, countKey).Int()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get login count: %w", err)
	}
	profile.LoginCount = count

	// Get last login time
	lastLoginKey := fmt.Sprintf("%s%s:last_login", behaviorKeyPrefix, userID)
	lastLoginStr, err := b.redis.Client.Get(ctx, lastLoginKey).Result()
	if err == nil {
		profile.LastLoginTime, _ = time.Parse(time.RFC3339, lastLoginStr)
	}

	// Get login hours distribution
	hourKey := fmt.Sprintf("%s%s:hours", behaviorKeyPrefix, userID)
	hourResults, err := b.redis.Client.ZRevRangeWithScores(ctx, hourKey, 0, -1).Result()
	if err == nil && len(hourResults) > 0 {
		var hours []int
		totalScore := 0.0

		for _, z := range hourResults {
			var hour int
			if _, err := fmt.Sscanf(z.Member.(string), "hour:%d", &hour); err == nil {
				hours = append(hours, hour)
				totalScore += z.Score
			}
		}

		profile.TypicalLoginHours = hours
		profile.LoginCount = int(totalScore)

		// Calculate mean and standard deviation
		if len(hours) > 0 {
			profile.AverageLoginHour = b.calculateWeightedMean(ctx, userID, hourKey)
			profile.LoginHourStdDev = b.calculateStdDev(ctx, userID, hourKey, profile.AverageLoginHour)
		}
	}

	// Get locations
	locationKey := fmt.Sprintf("%s%s:locations", behaviorKeyPrefix, userID)
	locationResults, err := b.redis.Client.ZRevRange(ctx, locationKey, 0, int64(b.config.MaxLocations-1)).Result()
	if err == nil {
		detailsKey := fmt.Sprintf("%s%s:location:details", behaviorKeyPrefix, userID)
		for _, locHash := range locationResults {
			locJSON, err := b.redis.Client.HGet(ctx, detailsKey, locHash).Result()
			if err == nil {
				var geo GeoPoint
				if json.Unmarshal([]byte(locJSON), &geo) == nil {
					profile.TypicalLocations = append(profile.TypicalLocations, geo)
				}
			}
		}
	}

	// Get devices
	deviceKey := fmt.Sprintf("%s%s:devices", behaviorKeyPrefix, userID)
	deviceResults, err := b.redis.Client.ZRevRange(ctx, deviceKey, 0, int64(b.config.MaxDevices-1)).Result()
	if err == nil {
		profile.TypicalDevices = deviceResults
	}

	// Get resources
	resourceKey := fmt.Sprintf("%s%s:resources", behaviorKeyPrefix, userID)
	resourceResults, err := b.redis.Client.ZRevRange(ctx, resourceKey, 0, int64(b.config.MaxResources-1)).Result()
	if err == nil {
		profile.TypicalResources = resourceResults
	}

	// Determine if profile is established
	profile.ProfileEstablished = profile.LoginCount >= b.config.MinLoginsForProfile

	return profile, nil
}

// DetectAnomalies checks for behavioral anomalies in a login attempt
func (b *BehaviorTracker) DetectAnomalies(ctx context.Context, userID, ip, userAgent string, lat, lon float64, loginTime time.Time) ([]string, int) {
	profile, err := b.GetBehaviorProfile(ctx, userID)
	if err != nil {
		b.logger.Warn("Failed to get behavior profile", zap.Error(err))
		return nil, 0
	}

	if !profile.ProfileEstablished {
		// Not enough data to establish baseline
		return nil, 0
	}

	var anomalies []string
	riskScore := 0

	// Check 1: Unusual login hour (>2 std dev from mean)
	loginHour := loginTime.UTC().Hour()
	if b.isAnomalousHour(loginHour, profile.AverageLoginHour, profile.LoginHourStdDev) {
		anomalies = append(anomalies, fmt.Sprintf("unusual_hour:%d", loginHour))
		riskScore += 25
	}

	// Check 2: New location (>500km from any known location)
	fingerprint := b.computeDeviceFingerprint(ip, userAgent)
	if lat != 0 && lon != 0 {
		isNewLocation, distance := b.isNewLocation(lat, lon, profile.TypicalLocations)
		if isNewLocation {
			anomalies = append(anomalies, fmt.Sprintf("new_location:%.0fkm", distance))
			riskScore += 30
		}
	}

	// Check 3: New device
	isNewDevice := true
	for _, device := range profile.TypicalDevices {
		if device == fingerprint {
			isNewDevice = false
			break
		}
	}
	if isNewDevice {
		anomalies = append(anomalies, "new_device")
		riskScore += 20
	}

	// High risk: new device + new location combination
	if isNewDevice && len(anomalies) > 1 {
		for _, anomaly := range anomalies {
			if len(anomaly) > 11 && anomaly[:12] == "new_location" {
				riskScore += 30 // Additional penalty for combo
				anomalies = append(anomalies, "new_device_location_combo")
			}
		}
	}

	return anomalies, riskScore
}

// isAnomalousHour checks if the hour is outside the typical pattern
func (b *BehaviorTracker) isAnomalousHour(hour int, mean, stdDev float64) bool {
	if stdDev == 0 {
		return false
	}

	// Calculate z-score
	zScore := math.Abs(float64(hour)-mean) / stdDev

	// More than 2 standard deviations is anomalous
	return zScore > b.config.StdDevThreshold
}

// isNewLocation checks if the location is far from all known locations
func (b *BehaviorTracker) isNewLocation(lat, lon float64, knownLocations []GeoPoint) (bool, float64) {
	if len(knownLocations) == 0 {
		return false, 0
	}

	minDistance := math.MaxFloat64

	for _, known := range knownLocations {
		if known.Latitude == 0 && known.Longitude == 0 {
			continue
		}
		distance := haversineDistance(known.Latitude, known.Longitude, lat, lon)
		if distance < minDistance {
			minDistance = distance
		}
	}

	return minDistance > b.config.LocationThresholdKm, minDistance
}

// calculateWeightedMean calculates the weighted mean of login hours
func (b *BehaviorTracker) calculateWeightedMean(ctx context.Context, userID, hourKey string) float64 {
	results, err := b.redis.Client.ZRevRangeWithScores(ctx, hourKey, 0, -1).Result()
	if err != nil || len(results) == 0 {
		return 12.0 // Default to noon
	}

	weightedSum := 0.0
	totalWeight := 0.0

	for _, z := range results {
		var hour int
		if _, err := fmt.Sscanf(z.Member.(string), "hour:%d", &hour); err == nil {
			weightedSum += float64(hour) * z.Score
			totalWeight += z.Score
		}
	}

	if totalWeight == 0 {
		return 12.0
	}

	return weightedSum / totalWeight
}

// calculateStdDev calculates standard deviation of login hours
func (b *BehaviorTracker) calculateStdDev(ctx context.Context, userID, hourKey string, mean float64) float64 {
	results, err := b.redis.Client.ZRevRangeWithScores(ctx, hourKey, 0, -1).Result()
	if err != nil || len(results) == 0 {
		return 4.0 // Default std dev
	}

	sumSquaredDiff := 0.0
	totalWeight := 0.0

	for _, z := range results {
		var hour int
		if _, err := fmt.Sscanf(z.Member.(string), "hour:%d", &hour); err == nil {
			diff := float64(hour) - mean
			sumSquaredDiff += (diff * diff) * z.Score
			totalWeight += z.Score
		}
	}

	if totalWeight == 0 {
		return 4.0
	}

	variance := sumSquaredDiff / totalWeight
	return math.Sqrt(variance)
}

// computeDeviceFingerprint generates a device fingerprint from IP and user agent
func (b *BehaviorTracker) computeDeviceFingerprint(ip, userAgent string) string {
	// Extract /24 subnet from IP
	subnet := ip
	parsedIP := parseIP(ip)
	if parsedIP != nil {
		ip4 := parsedIP.To4()
		if ip4 != nil {
			subnet = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}

	// Normalize user agent (simplified)
	normalizedUA := normalizeUserAgent(userAgent)

	return fmt.Sprintf("%s|%s", subnet, normalizedUA)
}

// normalizeUserAgent creates a normalized version of the user agent
func normalizeUserAgent(ua string) string {
	// Simple normalization - convert to lowercase
	ua = fmt.Sprintf("%s", ua)
	return ua
}

// GetTypicalLoginHours returns the user's typical login hours as a histogram
func (b *BehaviorTracker) GetTypicalLoginHours(ctx context.Context, userID string) (map[int]int, error) {
	hourKey := fmt.Sprintf("%s%s:hours", behaviorKeyPrefix, userID)
	results, err := b.redis.Client.ZRevRangeWithScores(ctx, hourKey, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	histogram := make(map[int]int)
	for _, z := range results {
		var hour int
		if _, err := fmt.Sscanf(z.Member.(string), "hour:%d", &hour); err == nil {
			histogram[hour] = int(z.Score)
		}
	}

	return histogram, nil
}

// ClearBehaviorProfile clears all behavior data for a user
func (b *BehaviorTracker) ClearBehaviorProfile(ctx context.Context, userID string) error {
	keys := []string{
		fmt.Sprintf("%s%s:hours", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:locations", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:location:details", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:devices", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:resources", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:last_login", behaviorKeyPrefix, userID),
		fmt.Sprintf("%s%s:count", behaviorKeyPrefix, userID),
	}

	return b.redis.Client.Del(ctx, keys...).Err()
}

// GetUserBehaviorSummary returns a summary of user behavior for UI display
func (b *BehaviorTracker) GetUserBehaviorSummary(ctx context.Context, userID string) (map[string]interface{}, error) {
	profile, err := b.GetBehaviorProfile(ctx, userID)
	if err != nil {
		return nil, err
	}

	summary := map[string]interface{}{
		"user_id":           profile.UserID,
		"login_count":       profile.LoginCount,
		"profile_established": profile.ProfileEstablished,
		"typical_hours":     profile.TypicalLoginHours,
		"avg_hour":          int(profile.AverageLoginHour),
		"location_count":    len(profile.TypicalLocations),
		"device_count":      len(profile.TypicalDevices),
		"resource_count":    len(profile.TypicalResources),
		"last_login":        profile.LastLoginTime,
	}

	return summary, nil
}

// haversineDistance calculates the distance between two geo points in km
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371 // km

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}

// parseIP is a helper to parse IP addresses
func parseIP(ip string) *net.IPAddr {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	return &net.IPAddr{IP: parsed}
}
