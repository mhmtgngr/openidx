// Package risk provides device fingerprinting and trust level assessment
package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// TrustLevel represents how trusted a device is
type TrustLevel string

const (
	TrustLevelTrusted    TrustLevel = "trusted"    // Seen 5+ times, explicitly trusted
	TrustLevelKnown      TrustLevel = "known"      // Seen before, but not yet 5 times
	TrustLevelUnknown    TrustLevel = "unknown"    // First time seen
	TrustLevelSuspicious TrustLevel = "suspicious" // Fingerprint changed for known device
)

// DeviceFingerprintRequest contains device attributes for fingerprinting
type DeviceFingerprintRequest struct {
	UserAgent   string `json:"user_agent"`
	ScreenRes   string `json:"screen_resolution"`   // e.g., "1920x1080"
	Timezone    string `json:"timezone"`            // e.g., "America/New_York"
	Language    string `json:"language"`            // e.g., "en-US"
	Platform    string `json:"platform"`            // e.g., "Win32", "MacIntel"
	IP          string `json:"ip_address"`
	CanvasHash  string `json:"canvas_hash,omitempty"`  // Optional: canvas fingerprint hash
	WebGLHash   string `json:"webgl_hash,omitempty"`   // Optional: WebGL fingerprint hash
	AudioHash   string `json:"audio_hash,omitempty"`   // Optional: audio fingerprint hash
}

// DeviceFingerprint represents a computed device fingerprint
type DeviceFingerprint struct {
	Hash         string    `json:"hash"`
	TrustLevel   TrustLevel `json:"trust_level"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SeenCount    int       `json:"seen_count"`
	UserID       string    `json:"user_id,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	IsTrusted    bool      `json:"is_trusted"`
	Attributes   DeviceFingerprintRequest `json:"attributes,omitempty"`
	PreviousHash string    `json:"previous_hash,omitempty"` // If fingerprint changed
}

// DeviceRecord represents a stored device record
type DeviceRecord struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Location    string    `json:"location"`
	Trusted     bool      `json:"trusted"`
	SeenCount   int       `json:"seen_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
}

// FingerprintingConfig holds configuration for device fingerprinting
type FingerprintingConfig struct {
	// Redis key expiration
	CacheTTL time.Duration

	// Trust thresholds
	TrustedThreshold int // Number of times seen before auto-trust (default 5)

	// Hash salt for additional security
	Salt string

	// Enable/disable optional fingerprinting components
	UseCanvasFingerprint bool
	UseWebGLFingerprint  bool
	UseAudioFingerprint  bool
}

// DefaultFingerprintingConfig returns default fingerprinting configuration
func DefaultFingerprintingConfig() FingerprintingConfig {
	return FingerprintingConfig{
		CacheTTL:             24 * time.Hour,
		TrustedThreshold:     5,
		Salt:                 "openidx-device-fingerprint",
		UseCanvasFingerprint: true,
		UseWebGLFingerprint:  true,
		UseAudioFingerprint:  false, // Disabled by default due to user experience concerns
	}
}

// DeviceFingerprinter handles device fingerprinting operations
type DeviceFingerprinter struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config FingerprintingConfig
	logger *zap.Logger
}

// NewDeviceFingerprinter creates a new device fingerprinter
func NewDeviceFingerprinter(db *database.PostgresDB, redis *database.RedisClient, config FingerprintingConfig, logger *zap.Logger) *DeviceFingerprinter {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.Salt == "" {
		config = DefaultFingerprintingConfig()
	}
	return &DeviceFingerprinter{
		db:     db,
		redis:  redis,
		config: config,
		logger: logger.With(zap.String("component", "device_fingerprinter")),
	}
}

// ComputeFingerprint generates a SHA256 hash from device attributes
// Format: UserAgent + ScreenRes + Timezone + Language + Platform (+ optional hashes)
func (f *DeviceFingerprinter) ComputeFingerprint(req DeviceFingerprintRequest) string {
	// Normalize inputs
	normalizedUA := normalizeUserAgent(req.UserAgent)
	normalizedScreen := normalizeScreenRes(req.ScreenRes)
	normalizedTimezone := normalizeTimezone(req.Timezone)
	normalizedLanguage := strings.ToLower(strings.TrimSpace(req.Language))
	normalizedPlatform := strings.TrimSpace(req.Platform)

	// Build fingerprint string
	fingerprintStr := fmt.Sprintf("%s|%s|%s|%s|%s",
		normalizedUA, normalizedScreen, normalizedTimezone, normalizedLanguage, normalizedPlatform)

	// Add optional components if enabled
	if f.config.UseCanvasFingerprint && req.CanvasHash != "" {
		fingerprintStr += "|" + req.CanvasHash
	}
	if f.config.UseWebGLFingerprint && req.WebGLHash != "" {
		fingerprintStr += "|" + req.WebGLHash
	}
	if f.config.UseAudioFingerprint && req.AudioHash != "" {
		fingerprintStr += "|" + req.AudioHash
	}

	// Add salt
	fingerprintStr += "|" + f.config.Salt

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(fingerprintStr))
	return hex.EncodeToString(hash[:])
}

// GetOrRegisterDevice retrieves or creates a device fingerprint record
// Returns the fingerprint, trust level, and whether it's new
func (f *DeviceFingerprinter) GetOrRegisterDevice(ctx context.Context, userID string, req DeviceFingerprintRequest) (*DeviceFingerprint, bool, error) {
	fingerprint := f.ComputeFingerprint(req)

	// Try to get from cache first
	cacheKey := fmt.Sprintf("device:%s:%s", userID, fingerprint)
	cached, err := f.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var fp DeviceFingerprint
		if json.Unmarshal([]byte(cached), &fp) == nil {
			// Update last seen time
			fp.LastSeen = time.Now()
			fp.SeenCount++
			fp.TrustLevel = f.calculateTrustLevel(fp.SeenCount)
			return &fp, false, nil
		}
	}

	// Query database for existing device
	var deviceID string
	var trusted bool
	var seenCount int
	var firstSeen, lastSeen time.Time

	dbErr := f.db.Pool.QueryRow(ctx,
		`SELECT id, trusted, seen_count, first_seen, last_seen
		 FROM known_devices
		 WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&deviceID, &trusted, &seenCount, &firstSeen, &lastSeen)

	if dbErr == nil {
		// Device exists - update it
		seenCount++
		lastSeen = time.Now()
		trustLevel := f.calculateTrustLevel(seenCount)

		_, err := f.db.Pool.Exec(ctx,
			`UPDATE known_devices
			 SET seen_count = $3, last_seen = $4, ip_address = $5, user_agent = $6
			 WHERE id = $1`,
			deviceID, userID, seenCount, lastSeen, req.IP, req.UserAgent)
		if err != nil {
			f.logger.Warn("Failed to update device record", zap.Error(err))
		}

		fp := &DeviceFingerprint{
			Hash:       fingerprint,
			TrustLevel: trustLevel,
			FirstSeen:  firstSeen,
			LastSeen:   lastSeen,
			SeenCount:  seenCount,
			UserID:     userID,
			IPAddress:  req.IP,
			UserAgent:  req.UserAgent,
			IsTrusted:  trusted || seenCount >= f.config.TrustedThreshold,
			Attributes: req,
		}

		// Cache the result
		if data, err := json.Marshal(fp); err == nil {
			f.redis.Client.Set(ctx, cacheKey, data, f.config.CacheTTL)
		}

		return fp, false, nil
	}

	// Check for suspicious activity - fingerprint change for same user
	suspicious, previousHash := f.checkForSuspiciousFingerprint(ctx, userID, fingerprint)

	// New device - create record
	now := time.Now()
	seenCount = 1
	trustLevel := f.calculateTrustLevel(seenCount)

	var newDeviceID string
	err = f.db.Pool.QueryRow(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, ip_address, user_agent, seen_count, first_seen, last_seen, trusted)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id`,
		userID, fingerprint, f.generateDeviceName(req.UserAgent), req.IP, req.UserAgent,
		seenCount, now, now, false).Scan(&newDeviceID)

	if err != nil {
		return nil, false, fmt.Errorf("failed to create device record: %w", err)
	}

	fp := &DeviceFingerprint{
		Hash:         fingerprint,
		TrustLevel:   TrustLevelUnknown,
		FirstSeen:    now,
		LastSeen:     now,
		SeenCount:    seenCount,
		UserID:       userID,
		IPAddress:    req.IP,
		UserAgent:    req.UserAgent,
		IsTrusted:    false,
		Attributes:   req,
		PreviousHash: previousHash,
	}

	// If suspicious, update trust level
	if suspicious {
		fp.TrustLevel = TrustLevelSuspicious
		f.logger.Warn("Suspicious device fingerprint detected",
			zap.String("user_id", userID),
			zap.String("new_hash", fingerprint),
			zap.String("previous_hash", previousHash),
		)
	}

	// Cache the result
	if data, err := json.Marshal(fp); err == nil {
		f.redis.Client.Set(ctx, cacheKey, data, f.config.CacheTTL)
	}

	f.logger.Info("New device registered",
		zap.String("user_id", userID),
		zap.String("fingerprint", fingerprint[:16]+"..."),
		zap.String("trust_level", string(fp.TrustLevel)),
	)

	return fp, true, nil
}

// GetDeviceTrustLevel returns the trust level for a device fingerprint
func (f *DeviceFingerprinter) GetDeviceTrustLevel(ctx context.Context, userID, fingerprint string) TrustLevel {
	var seenCount int
	var trusted bool

	err := f.db.Pool.QueryRow(ctx,
		`SELECT seen_count, trusted FROM known_devices
		 WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint).Scan(&seenCount, &trusted)

	if err != nil {
		return TrustLevelUnknown
	}

	if trusted {
		return TrustLevelTrusted
	}

	return f.calculateTrustLevel(seenCount)
}

// TrustDevice marks a device as trusted
func (f *DeviceFingerprinter) TrustDevice(ctx context.Context, userID, fingerprint string) error {
	_, err := f.db.Pool.Exec(ctx,
		`UPDATE known_devices SET trusted = true WHERE user_id = $1 AND fingerprint = $2`,
		userID, fingerprint)

	if err != nil {
		return fmt.Errorf("failed to trust device: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("device:%s:%s", userID, fingerprint)
	f.redis.Client.Del(ctx, cacheKey)

	f.logger.Info("Device marked as trusted",
		zap.String("user_id", userID),
		zap.String("fingerprint", fingerprint[:16]+"..."),
	)

	return nil
}

// RevokeDevice removes trust from a device or deletes it
func (f *DeviceFingerprinter) RevokeDevice(ctx context.Context, userID, fingerprint string, delete bool) error {
	var err error

	if delete {
		_, err = f.db.Pool.Exec(ctx,
			`DELETE FROM known_devices WHERE user_id = $1 AND fingerprint = $2`,
			userID, fingerprint)
	} else {
		_, err = f.db.Pool.Exec(ctx,
			`UPDATE known_devices SET trusted = false WHERE user_id = $1 AND fingerprint = $2`,
			userID, fingerprint)
	}

	if err != nil {
		return fmt.Errorf("failed to revoke device: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("device:%s:%s", userID, fingerprint)
	f.redis.Client.Del(ctx, cacheKey)

	return nil
}

// GetUserDevices returns all devices for a user
func (f *DeviceFingerprinter) GetUserDevices(ctx context.Context, userID string) ([]DeviceRecord, error) {
	rows, err := f.db.Pool.Query(ctx,
		`SELECT id, user_id, fingerprint, name, ip_address, user_agent, location,
		        trusted, seen_count, first_seen, last_seen, created_at
		 FROM known_devices
		 WHERE user_id = $1
		 ORDER BY last_seen DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []DeviceRecord
	for rows.Next() {
		var d DeviceRecord
		err := rows.Scan(&d.ID, &d.UserID, &d.Fingerprint, &d.Name, &d.IPAddress,
			&d.UserAgent, &d.Location, &d.Trusted, &d.SeenCount,
			&d.FirstSeen, &d.LastSeen, &d.CreatedAt)
		if err != nil {
			continue
		}
		devices = append(devices, d)
	}

	return devices, nil
}

// calculateTrustLevel determines trust level based on seen count
func (f *DeviceFingerprinter) calculateTrustLevel(seenCount int) TrustLevel {
	if seenCount >= f.config.TrustedThreshold {
		return TrustLevelTrusted
	}
	if seenCount > 1 {
		return TrustLevelKnown
	}
	return TrustLevelUnknown
}

// checkForSuspiciousFingerprint checks if the fingerprint represents a change
// from a previously known device for the same user
func (f *DeviceFingerprinter) checkForSuspiciousFingerprint(ctx context.Context, userID, newFingerprint string) (bool, string) {
	// Get recent devices for this user
	rows, err := f.db.Pool.Query(ctx,
		`SELECT fingerprint, seen_count FROM known_devices
		 WHERE user_id = $1
		 ORDER BY last_seen DESC
		 LIMIT 5`,
		userID)
	if err != nil {
		return false, ""
	}
	defer rows.Close()

	var previousHash string
	maxSeenCount := 0

	for rows.Next() {
		var fp string
		var count int
		if rows.Scan(&fp, &count) == nil {
			if fp != newFingerprint && count > maxSeenCount {
				maxSeenCount = count
				previousHash = fp
			}
		}
	}

	// Suspicious if we're replacing a well-known device
	if previousHash != "" && maxSeenCount >= 3 {
		return true, previousHash
	}

	return false, ""
}

// generateDeviceName creates a human-readable name from user agent
func (f *DeviceFingerprinter) generateDeviceName(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Detect OS
	var os string
	switch {
	case strings.Contains(ua, "windows nt 10.0") || strings.Contains(ua, "windows 10"):
		os = "Windows 10"
	case strings.Contains(ua, "windows nt 11.0") || strings.Contains(ua, "windows 11"):
		os = "Windows 11"
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macos"):
		os = "macOS"
	case strings.Contains(ua, "iphone"):
		os = "iPhone"
	case strings.Contains(ua, "ipad"):
		os = "iPad"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	default:
		os = "Unknown OS"
	}

	// Detect browser
	var browser string
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edge/"):
		browser = "Edge"
	case strings.Contains(ua, "chrome/") && !strings.Contains(ua, "edg"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "opera") || strings.Contains(ua, "opr/"):
		browser = "Opera"
	default:
		browser = "Browser"
	}

	return fmt.Sprintf("%s on %s", browser, os)
}

// Helper functions for normalization

// normalizeUserAgent normalizes user agent string for fingerprinting
func normalizeUserAgent(ua string) string {
	// Convert to lowercase and trim
	ua = strings.ToLower(strings.TrimSpace(ua))

	// Remove version numbers for browser engines (they change frequently)
	// Keep browser name and major version
	re := regexp.MustCompile(`(chrome|firefox|safari|edge|edg|opera|opr)/\d+\.\d+\.\d+\.\d+`)
	ua = re.ReplaceAllString(ua, "$1")

	// Normalize Windows version strings
	re = regexp.MustCompile(`windows nt \d+\.\d+`)
	ua = re.ReplaceAllString(ua, "windows nt")

	// Normalize macOS version strings
	re = regexp.MustCompile(`mac os x \d+_[\d_]+`)
	ua = re.ReplaceAllString(ua, "mac os x")

	// Normalize Android version strings
	re = regexp.MustCompile(`android \d+\.\d+(\.\d+)?`)
	ua = re.ReplaceAllString(ua, "android")

	return ua
}

// normalizeScreenRes normalizes screen resolution
func normalizeScreenRes(res string) string {
	res = strings.ToLower(strings.TrimSpace(res))

	// Common resolutions grouped
	switch {
	case res == "" || res == "unknown":
		return "unknown"
	case strings.HasPrefix(res, "1920x1080") || res == "1920x1080":
		return "fhd"
	case strings.HasPrefix(res, "2560x1440") || res == "2560x1440":
		return "qhd"
	case strings.HasPrefix(res, "3840x2160") || res == "3840x2160":
		return "4k"
	case strings.HasPrefix(res, "1366x768") || res == "1366x768":
		return "laptop-hd"
	case strings.HasPrefix(res, "1440x900") || res == "1440x900":
		return "macbook"
	case strings.HasPrefix(res, "1280x720") || res == "1280x720":
		return "hd"
	case strings.HasPrefix(res, "mobile-"):
		return "mobile"
	default:
		// For other resolutions, normalize to categories
		parts := strings.Split(res, "x")
		if len(parts) == 2 {
			width := strings.TrimSpace(parts[0])
			// Just keep width bucketed
			if len(width) >= 4 {
				return width[:3] + "xxx"
			}
		}
		return "other"
	}
}

// normalizeTimezone normalizes timezone string
func normalizeTimezone(tz string) string {
	tz = strings.TrimSpace(tz)

	if tz == "" || tz == "UTC" || tz == "GMT" {
		return "utc"
	}

	// Normalize to timezone region (everything before /)
	if parts := strings.Split(tz, "/"); len(parts) > 1 {
		return strings.ToLower(parts[0])
	}

	return strings.ToLower(tz)
}

// IsPrivateIP checks if an IP is private/local
func IsPrivateIP(ip string) bool {
	parsedIP := parseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := parseCIDR(cidr)
		if ipNet != nil && ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// parseIP is a helper to parse IP addresses
func parseIP(ip string) interface{} {
	// This would use net.ParseIP in actual implementation
	// For now, return nil as placeholder
	return nil
}

// parseCIDR is a helper to parse CIDR notation
func parseCIDR(cidr string) (interface{}, interface{}, error) {
	// This would use net.ParseCIDR in actual implementation
	// For now, return nil as placeholder
	return nil, nil, nil
}

// Redis keys for device tracking
const (
	DeviceCacheKeyPrefix  = "device:fingerprint:"
	DeviceUserKeyPrefix   = "device:user:"
	DeviceBlocklistPrefix = "device:blocklist:"
)

// SetDeviceCache sets device fingerprint data in Redis
func (f *DeviceFingerprinter) SetDeviceCache(ctx context.Context, fingerprint string, data interface{}, ttl time.Duration) error {
	key := DeviceCacheKeyPrefix + fingerprint
	serialized, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return f.redis.Client.Set(ctx, key, serialized, ttl).Err()
}

// GetDeviceCache retrieves device fingerprint data from Redis
func (f *DeviceFingerprinter) GetDeviceCache(ctx context.Context, fingerprint string, dest interface{}) error {
	key := DeviceCacheKeyPrefix + fingerprint
	data, err := f.redis.Client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // Not found
		}
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// InvalidateDeviceCache removes cached device data
func (f *DeviceFingerprinter) InvalidateDeviceCache(ctx context.Context, fingerprint string) error {
	key := DeviceCacheKeyPrefix + fingerprint
	return f.redis.Client.Del(ctx, key).Err()
}
