package risk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// GeoResult represents a geo-IP lookup result
type GeoResult struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Query       string  `json:"query"`
}

// Device represents a known device for a user
type Device struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Location    string    `json:"location"`
	Trusted     bool      `json:"trusted"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// LoginRecord represents a login history entry
type LoginRecord struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Location          string    `json:"location"`
	Latitude          float64   `json:"latitude"`
	Longitude         float64   `json:"longitude"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	RiskScore         int       `json:"risk_score"`
	Success           bool      `json:"success"`
	AuthMethods       []string  `json:"auth_methods"`
	CreatedAt         time.Time `json:"created_at"`
}

// Service provides risk assessment and device management
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	logger *zap.Logger
}

// NewService creates a new risk service
func NewService(db *database.PostgresDB, redis *database.RedisClient, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger.With(zap.String("component", "risk")),
	}
}

// ComputeDeviceFingerprint generates a SHA256 fingerprint from IP subnet and User-Agent
func (s *Service) ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	// Extract /24 subnet from IP
	subnet := ipAddress
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			subnet = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}

	hash := sha256.Sum256([]byte(subnet + "|" + userAgent))
	return fmt.Sprintf("%x", hash)
}

// RegisterDevice registers or updates a known device for a user
func (s *Service) RegisterDevice(ctx context.Context, userID, fingerprint, ipAddress, userAgent, location string) (string, bool, error) {
	// Try to find existing device
	var deviceID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&deviceID)

	if err == nil {
		// Device exists — update last seen
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE known_devices SET last_seen_at = NOW(), ip_address = $3, location = $4 WHERE id = $1`,
			deviceID, userID, ipAddress, location); err != nil {
			return deviceID, false, fmt.Errorf("failed to update device: %w", err)
		}
		return deviceID, false, nil
	}

	// New device — insert
	name := parseDeviceName(userAgent)
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, ip_address, user_agent, location)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen_at = NOW()
		 RETURNING id`,
		userID, fingerprint, name, ipAddress, userAgent, location).Scan(&deviceID)
	if err != nil {
		return "", false, fmt.Errorf("failed to register device: %w", err)
	}

	s.logger.Info("New device registered",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID),
		zap.String("ip", ipAddress),
		zap.String("location", location),
	)

	return deviceID, true, nil
}

// IsDeviceTrusted checks if a device is trusted for a user
func (s *Service) IsDeviceTrusted(ctx context.Context, userID, fingerprint string) bool {
	var trusted bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT trusted FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&trusted)
	if err != nil {
		return false
	}
	return trusted
}

// GetUserDevices returns all known devices for a user
func (s *Service) GetUserDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, fingerprint, COALESCE(name,''), COALESCE(ip_address,''), COALESCE(user_agent,''),
		        COALESCE(location,''), trusted, last_seen_at, created_at
		 FROM known_devices WHERE user_id = $1 ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted, &d.LastSeenAt, &d.CreatedAt); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// GetAllDevices returns all known devices (admin)
func (s *Service) GetAllDevices(ctx context.Context, limit, offset int) ([]Device, int, error) {
	var total int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices`).Scan(&total)

	rows, err := s.db.Pool.Query(ctx,
		`SELECT d.id, d.user_id, d.fingerprint, COALESCE(d.name,''), COALESCE(d.ip_address,''),
		        COALESCE(d.user_agent,''), COALESCE(d.location,''), d.trusted, d.last_seen_at, d.created_at
		 FROM known_devices d ORDER BY d.last_seen_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted, &d.LastSeenAt, &d.CreatedAt); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, total, nil
}

// TrustDevice marks a device as trusted
func (s *Service) TrustDevice(ctx context.Context, deviceID string) error {
	_, err := s.db.Pool.Exec(ctx,
		`UPDATE known_devices SET trusted = true WHERE id = $1`, deviceID)
	return err
}

// RevokeDevice removes trust or deletes a device
func (s *Service) RevokeDevice(ctx context.Context, deviceID string) error {
	_, err := s.db.Pool.Exec(ctx,
		`DELETE FROM known_devices WHERE id = $1`, deviceID)
	return err
}

// RecordLogin records a login attempt in history
func (s *Service) RecordLogin(ctx context.Context, userID, ip, userAgent, location string, lat, lon float64, fingerprint string, success bool, authMethods []string, riskScore int) {
	_, err := s.db.Pool.Exec(ctx,
		`INSERT INTO login_history (user_id, ip_address, user_agent, location, latitude, longitude, device_fingerprint, risk_score, success, auth_methods)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		userID, ip, userAgent, location, lat, lon, fingerprint, riskScore, success, authMethods)
	if err != nil {
		s.logger.Error("Failed to record login", zap.Error(err))
	}
}

// GetLoginHistory returns recent login history
func (s *Service) GetLoginHistory(ctx context.Context, userID string, limit int) ([]LoginRecord, error) {
	query := `SELECT id, user_id, ip_address, COALESCE(user_agent,''), COALESCE(location,''),
	                 COALESCE(latitude,0), COALESCE(longitude,0), COALESCE(device_fingerprint,''),
	                 risk_score, success, COALESCE(auth_methods,'{}'), created_at
	          FROM login_history`
	args := []interface{}{}

	if userID != "" {
		query += ` WHERE user_id = $1`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC`

	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []LoginRecord
	for rows.Next() {
		var r LoginRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.IPAddress, &r.UserAgent, &r.Location,
			&r.Latitude, &r.Longitude, &r.DeviceFingerprint, &r.RiskScore, &r.Success,
			&r.AuthMethods, &r.CreatedAt); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

// CalculateRiskScore calculates a risk score for a login attempt
func (s *Service) CalculateRiskScore(ctx context.Context, userID, ip, userAgent, fingerprint, location string, lat, lon float64) (int, []string) {
	score := 0
	var factors []string

	// Factor 1: New device (+30)
	var deviceCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&deviceCount)
	if deviceCount == 0 {
		score += 30
		factors = append(factors, "new_device")
	}

	// Factor 2: Unusual location (+25) — country differs from last 5 logins
	if location != "" {
		country := extractCountry(location)
		rows, err := s.db.Pool.Query(ctx,
			`SELECT DISTINCT location FROM login_history
			 WHERE user_id = $1 AND success = true
			 ORDER BY location LIMIT 5`, userID)
		if err == nil {
			defer rows.Close()
			knownCountries := make(map[string]bool)
			for rows.Next() {
				var loc string
				if rows.Scan(&loc) == nil {
					knownCountries[extractCountry(loc)] = true
				}
			}
			if len(knownCountries) > 0 && !knownCountries[country] {
				score += 25
				factors = append(factors, "unusual_location")
			}
		}
	}

	// Factor 3: Failed login attempts in last hour (+10 each, max +50)
	var failedCount int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE user_id = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour'`,
		userID).Scan(&failedCount)
	if failedCount > 0 {
		addition := failedCount * 10
		if addition > 50 {
			addition = 50
		}
		score += addition
		factors = append(factors, fmt.Sprintf("failed_attempts_%d", failedCount))
	}

	// Factor 4: Impossible travel (+50)
	if lat != 0 && lon != 0 {
		if s.detectImpossibleTravel(ctx, userID, lat, lon) {
			score += 50
			factors = append(factors, "impossible_travel")
		}
	}

	// Factor 5: Off-hours login (+10) — before 6am or after 10pm UTC
	hour := time.Now().UTC().Hour()
	if hour < 6 || hour >= 22 {
		score += 10
		factors = append(factors, "off_hours")
	}

	// Factor 6: First login from this country ever (+15)
	if location != "" {
		country := extractCountry(location)
		var countryCount int
		s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM login_history WHERE user_id = $1 AND location LIKE $2 AND success = true`,
			userID, "%"+country).Scan(&countryCount)
		if countryCount == 0 {
			score += 15
			factors = append(factors, "first_country_login")
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	s.logger.Debug("Risk score calculated",
		zap.String("user_id", userID),
		zap.Int("score", score),
		zap.Strings("factors", factors),
	)

	return score, factors
}

// detectImpossibleTravel checks if the user could have physically traveled from their last login location
func (s *Service) detectImpossibleTravel(ctx context.Context, userID string, lat, lon float64) bool {
	var lastLat, lastLon float64
	var lastTime time.Time

	err := s.db.Pool.QueryRow(ctx,
		`SELECT latitude, longitude, created_at FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0 AND longitude != 0
		 ORDER BY created_at DESC LIMIT 1`, userID).Scan(&lastLat, &lastLon, &lastTime)
	if err != nil {
		return false
	}

	distance := haversineDistance(lastLat, lastLon, lat, lon)
	timeDelta := time.Since(lastTime)

	// If more than 500km in less than 1 hour → impossible travel
	if distance > 500 && timeDelta < time.Hour {
		s.logger.Warn("Impossible travel detected",
			zap.String("user_id", userID),
			zap.Float64("distance_km", distance),
			zap.Duration("time_delta", timeDelta),
		)
		return true
	}

	return false
}

// GeoIPLookup performs a geo-IP lookup with Redis caching
func (s *Service) GeoIPLookup(ctx context.Context, ip string) (*GeoResult, error) {
	// Skip private/local IPs
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return &GeoResult{Country: "Local", CountryCode: "LO", City: "Local", Query: ip}, nil
	}

	// Check Redis cache
	cacheKey := "geoip:" + ip
	cached, err := s.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var result GeoResult
		if json.Unmarshal([]byte(cached), &result) == nil {
			return &result, nil
		}
	}

	// Call ip-api.com (free tier)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode,city,lat,lon,isp,query", ip))
	if err != nil {
		return nil, fmt.Errorf("geo-IP lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("geo-IP read failed: %w", err)
	}

	var result GeoResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("geo-IP parse failed: %w", err)
	}

	// Cache for 24 hours
	data, _ := json.Marshal(result)
	s.redis.Client.Set(ctx, cacheKey, string(data), 24*time.Hour)

	return &result, nil
}

// GetRiskStats returns risk statistics for the dashboard
func (s *Service) GetRiskStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// High-risk logins today
	var highRiskToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history WHERE risk_score >= 50 AND created_at > CURRENT_DATE`).Scan(&highRiskToday)
	stats["high_risk_logins_today"] = highRiskToday

	// New devices today
	var newDevicesToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM known_devices WHERE created_at > CURRENT_DATE`).Scan(&newDevicesToday)
	stats["new_devices_today"] = newDevicesToday

	// Total known devices
	var totalDevices int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices`).Scan(&totalDevices)
	stats["total_devices"] = totalDevices

	// Trusted devices
	var trustedDevices int
	s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM known_devices WHERE trusted = true`).Scan(&trustedDevices)
	stats["trusted_devices"] = trustedDevices

	// Failed logins today
	var failedToday int
	s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history WHERE success = false AND created_at > CURRENT_DATE`).Scan(&failedToday)
	stats["failed_logins_today"] = failedToday

	// Average risk score today
	var avgRisk *float64
	s.db.Pool.QueryRow(ctx,
		`SELECT AVG(risk_score) FROM login_history WHERE created_at > CURRENT_DATE AND success = true`).Scan(&avgRisk)
	if avgRisk != nil {
		stats["avg_risk_score_today"] = int(*avgRisk)
	} else {
		stats["avg_risk_score_today"] = 0
	}

	return stats, nil
}

// CreateStepUpChallenge creates a step-up MFA challenge for a session
func (s *Service) CreateStepUpChallenge(ctx context.Context, userID, sessionID, reason string) (string, error) {
	var challengeID string
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO stepup_challenges (user_id, session_id, reason, expires_at)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')
		 RETURNING id`,
		userID, sessionID, reason).Scan(&challengeID)
	if err != nil {
		return "", fmt.Errorf("failed to create step-up challenge: %w", err)
	}

	// Store in Redis for fast lookup
	s.redis.Client.Set(ctx, "stepup:"+challengeID, userID, 5*time.Minute)

	return challengeID, nil
}

// CompleteStepUpChallenge marks a step-up challenge as completed
func (s *Service) CompleteStepUpChallenge(ctx context.Context, challengeID, userID string) error {
	// Verify challenge belongs to user and is pending
	var status string
	var storedUserID string
	var expiresAt time.Time
	err := s.db.Pool.QueryRow(ctx,
		`SELECT user_id, status, expires_at FROM stepup_challenges WHERE id = $1`,
		challengeID).Scan(&storedUserID, &status, &expiresAt)
	if err != nil {
		return fmt.Errorf("challenge not found")
	}
	if storedUserID != userID {
		return fmt.Errorf("challenge does not belong to user")
	}
	if status != "pending" {
		return fmt.Errorf("challenge already %s", status)
	}
	if time.Now().After(expiresAt) {
		s.db.Pool.Exec(ctx, `UPDATE stepup_challenges SET status = 'expired' WHERE id = $1`, challengeID)
		return fmt.Errorf("challenge expired")
	}

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE stepup_challenges SET status = 'completed', completed_at = NOW() WHERE id = $1`, challengeID)
	if err != nil {
		return err
	}

	s.redis.Client.Del(ctx, "stepup:"+challengeID)
	return nil
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

// extractCountry extracts the country portion from a "City, Country" string
func extractCountry(location string) string {
	parts := strings.Split(location, ", ")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return location
}

// parseDeviceName generates a human-readable device name from User-Agent
func parseDeviceName(userAgent string) string {
	ua := strings.ToLower(userAgent)
	var os, browser string

	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	default:
		os = "Unknown OS"
	}

	switch {
	case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "edg"):
		browser = "Edge"
	default:
		browser = "Browser"
	}

	return browser + " on " + os
}
