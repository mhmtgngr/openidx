// Package risk provides IP intelligence including GeoIP lookup, VPN/Tor detection, and impossible travel detection
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/redis/go-redis/v9" // Imported for side effects
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// GeoIPResult represents the result of a GeoIP lookup
type GeoIPResult struct {
	IPAddress   string  `json:"ip_address"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Org         string  `json:"organization"`
	ASNumber    string  `json:"as_number"`
	IsMobile    bool    `json:"is_mobile"`
	IsProxy     bool    `json:"is_proxy"`
	IsVPN       bool    `json:"is_vpn"`
	IsTor       bool    `json:"is_tor"`
	IsHosting   bool    `json:"is_hosting"`
	ThreatScore int     `json:"threat_score"`
	LookupTime  time.Time `json:"lookup_time"`
}

// IPBlocklistEntry represents an IP address or range on the blocklist
type IPBlocklistEntry struct {
	ID          string     `json:"id"`
	IPAddress   string     `json:"ip_address"`   // Can be single IP or CIDR
	CIDR        string     `json:"cidr,omitempty"`
	Reason      string     `json:"reason"`
	ThreatType  string     `json:"threat_type"` // malware, botnet, brute-force, etc
	Source      string     `json:"source"`      // manual, abuseipdb, auto, etc
	Permanent   bool       `json:"permanent"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ReportCount int        `json:"report_count"`
}

// IPAllowlistEntry represents an IP address or range on the allowlist
type IPAllowlistEntry struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ip_address"`
	CIDR      string    `json:"cidr,omitempty"`
	Label     string    `json:"label"` // office, vpn, partner, etc
	CreatedAt time.Time `json:"created_at"`
}

// ImpossibleTravelResult represents the result of an impossible travel check
type ImpossibleTravelResult struct {
	IsImpossible   bool      `json:"is_impossible"`
	DistanceKm     float64   `json:"distance_km"`
	TimeDelta      time.Duration `json:"time_delta"`
	RequiredTime   time.Duration `json:"required_time"`
	SpeedKmh       float64   `json:"speed_kmh"`
	PreviousLocation *GeoPoint `json:"previous_location,omitempty"`
	CurrentLocation  *GeoPoint `json:"current_location,omitempty"`
	PreviousTime    time.Time `json:"previous_time"`
	CurrentTime     time.Time `json:"current_time"`
}

// IPIntelligenceConfig holds configuration for IP intelligence
type IPIntelligenceConfig struct {
	// GeoIP configuration
	GeoIPCacheTTL      time.Duration
	GeoIPProvider      string // "maxmind", "ip-api", "ipinfo"
	GeoIDatabasePath   string // Path to MaxMind GeoLite2 database

	// VPN/Tor detection
	EnableVPNDetection bool
	EnableTorDetection bool
	VPNCacheTTL        time.Duration

	// Impossible travel
	MaxTravelSpeed     float64 // km/h (default 900 = commercial aircraft)
	MinDistanceCheck   float64 // km (default 100)

	// Blocklist/Allowlist
	BlocklistCacheTTL  time.Duration
	EnableBlocklist    bool
	EnableAllowlist    bool

	// HTTP client for external APIs
	HTTPTimeout        time.Duration
}

// DefaultIPIntelligenceConfig returns default IP intelligence configuration
func DefaultIPIntelligenceConfig() IPIntelligenceConfig {
	return IPIntelligenceConfig{
		GeoIPCacheTTL:      24 * time.Hour,
		GeoIPProvider:      "ip-api", // Free tier default
		EnableVPNDetection: true,
		EnableTorDetection: true,
		VPNCacheTTL:        6 * time.Hour,
		MaxTravelSpeed:     900, // ~900 km/h (aircraft speed)
		MinDistanceCheck:   100,  // km
		BlocklistCacheTTL:  1 * time.Hour,
		EnableBlocklist:    true,
		EnableAllowlist:    true,
		HTTPTimeout:        5 * time.Second,
	}
}

// IPIntelligence provides IP-based risk assessment
type IPIntelligence struct {
	db      *database.PostgresDB
	redis   *database.RedisClient
	config  IPIntelligenceConfig
	client  *http.Client
	logger  *zap.Logger

	// In-memory caches for fast lookups
	torExitNodes map[string]struct{} // Set of known Tor exit IPs
	torMutex     sync.RWMutex
	vpnRanges    []*net.IPNet
	vpnMutex     sync.RWMutex
}

// NewIPIntelligence creates a new IP intelligence service
func NewIPIntelligence(db *database.PostgresDB, redis *database.RedisClient, config IPIntelligenceConfig, logger *zap.Logger) *IPIntelligence {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 5 * time.Second
	}

	return &IPIntelligence{
		db:      db,
		redis:   redis,
		config:  config,
		client:  &http.Client{Timeout: config.HTTPTimeout},
		logger:  logger.With(zap.String("component", "ip_intelligence")),
		torExitNodes: make(map[string]struct{}),
	}
}

// LookupGeoIP performs a GeoIP lookup with caching
func (i *IPIntelligence) LookupGeoIP(ctx context.Context, ip string) (*GeoIPResult, error) {
	// Check for private/local IPs first
	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() {
			return &GeoIPResult{
				IPAddress:  ip,
				Country:    "Local",
				CountryCode: "LO",
				City:       "Local",
				LookupTime: time.Now(),
			}, nil
		}
	}

	// Check Redis cache
	cacheKey := fmt.Sprintf("geoip:%s", ip)
	cached, err := i.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var result GeoIPResult
		if json.Unmarshal([]byte(cached), &result) == nil {
			return &result, nil
		}
	}

	// Perform GeoIP lookup based on configured provider
	var result *GeoIPResult
	switch i.config.GeoIPProvider {
	case "ip-api":
		result, err = i.lookupIPAPI(ctx, ip)
	case "maxmind":
		result, err = i.lookupMaxMind(ctx, ip)
	default:
		result, err = i.lookupIPAPI(ctx, ip) // Default fallback
	}

	if err != nil {
		return nil, fmt.Errorf("geoip lookup failed: %w", err)
	}

	// Enrich with VPN/Tor detection if enabled
	if i.config.EnableVPNDetection || i.config.EnableTorDetection {
		result.IsVPN = i.IsVPN(ctx, ip)
		result.IsTor = i.IsTorExitNode(ctx, ip)
		if result.IsVPN || result.IsTor {
			result.IsProxy = true
		}
	}

	// Cache the result
	data, _ := json.Marshal(result)
	i.redis.Client.Set(ctx, cacheKey, data, i.config.GeoIPCacheTTL)

	return result, nil
}

// lookupIPAPI uses ip-api.com for GeoIP lookup (free tier)
func (i *IPIntelligence) lookupIPAPI(ctx context.Context, ip string) (*GeoIPResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,region,lat,lon,isp,org,as,proxy,hosting,query", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Region      string  `json:"regionName"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
		Query       string  `json:"query"`
	}

	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, err
	}

	if apiResponse.Status != "success" {
		return nil, fmt.Errorf("ip-api returned status: %s", apiResponse.Status)
	}

	// Parse AS number
	asNumber := ""
	if parts := strings.Split(apiResponse.AS, " "); len(parts) > 0 {
		asNumber = parts[0]
	}

	return &GeoIPResult{
		IPAddress:   apiResponse.Query,
		Country:     apiResponse.Country,
		CountryCode: apiResponse.CountryCode,
		City:        apiResponse.City,
		Region:      apiResponse.Region,
		Latitude:    apiResponse.Lat,
		Longitude:   apiResponse.Lon,
		ISP:         apiResponse.ISP,
		Org:         apiResponse.Org,
		ASNumber:    asNumber,
		IsProxy:     apiResponse.Proxy,
		IsHosting:   apiResponse.Hosting,
		LookupTime:  time.Now(),
	}, nil
}

// lookupMaxMind uses MaxMind GeoLite2 database for GeoIP lookup
// This is a placeholder - actual implementation would use the MaxMind Go library
func (i *IPIntelligence) lookupMaxMind(ctx context.Context, ip string) (*GeoIPResult, error) {
	// Placeholder for MaxMind implementation
	// In production, this would use github.com/oschwald/geoip2-golang
	return &GeoIPResult{
		IPAddress:  ip,
		Country:    "Unknown",
		CountryCode: "??",
		LookupTime: time.Now(),
	}, fmt.Errorf("maxmind provider not configured")
}

// IsTorExitNode checks if an IP is a known Tor exit node
func (i *IPIntelligence) IsTorExitNode(ctx context.Context, ip string) bool {
	// Check in-memory cache first
	i.torMutex.RLock()
	_, exists := i.torExitNodes[ip]
	i.torMutex.RUnlock()

	if exists {
		return true
	}

	// Check Redis cache
	cacheKey := fmt.Sprintf("tor:exit:%s", ip)
	cached, err := i.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil && cached == "1" {
		i.torMutex.Lock()
		i.torExitNodes[ip] = struct{}{}
		i.torMutex.Unlock()
		return true
	}

	// Check database
	var isTor bool
	err = i.db.Pool.QueryRow(ctx,
		`SELECT is_tor FROM ip_threat_list WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&isTor)
	if err == nil && isTor {
		// Add to cache
		i.redis.Client.Set(ctx, cacheKey, "1", i.config.VPNCacheTTL)
		i.torMutex.Lock()
		i.torExitNodes[ip] = struct{}{}
		i.torMutex.Unlock()
		return true
	}

	return false
}

// IsVPN checks if an IP is from a known VPN provider
func (i *IPIntelligence) IsVPN(ctx context.Context, ip string) bool {
	// Check if IP matches known VPN CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	i.vpnMutex.RLock()
	defer i.vpnMutex.RUnlock()

	for _, ipNet := range i.vpnRanges {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	// Check database
	var isVPN bool
	err := i.db.Pool.QueryRow(ctx,
		`SELECT is_vpn FROM ip_threat_list WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&isVPN)
	if err == nil && isVPN {
		return true
	}

	// Check GeoIP result for VPN indicators
	geoResult, err := i.LookupGeoIP(ctx, ip)
	if err == nil {
		// Check if ISP name indicates VPN
		vpnKeywords := []string{"vpn", "virtual private", "nordvpn", "expressvpn",
			"cyberghost", "private internet access", "pia", "mullvad",
			"protonvpn", "surfshark", "hidemyass", "hma"}
		ispLower := strings.ToLower(geoResult.ISP)
		orgLower := strings.ToLower(geoResult.Org)

		for _, keyword := range vpnKeywords {
			if strings.Contains(ispLower, keyword) || strings.Contains(orgLower, keyword) {
				return true
			}
		}

		// Check AS number against known VPN ASNs
		vpnASNs := []string{"51177", "20473", "24940", "24961", "25152", "39421", "49981"}
		for _, asn := range vpnASNs {
			if geoResult.ASNumber == asn {
				return true
			}
		}
	}

	return false
}

// CheckBlocklist checks if an IP is on the blocklist
func (i *IPIntelligence) CheckBlocklist(ctx context.Context, ip string) (bool, *IPBlocklistEntry) {
	// Check exact match first
	var entry IPBlocklistEntry
	err := i.db.Pool.QueryRow(ctx,
		`SELECT id, ip_address, cidr, reason, threat_type, source, permanent, blocked_until, created_at, updated_at, report_count
		 FROM ip_blocklist
		 WHERE ip_address = $1 AND (permanent = true OR blocked_until > NOW())`,
		ip).Scan(&entry.ID, &entry.IPAddress, &entry.CIDR, &entry.Reason, &entry.ThreatType,
		&entry.Source, &entry.Permanent, &entry.BlockedUntil, &entry.CreatedAt, &entry.UpdatedAt, &entry.ReportCount)

	if err == nil {
		return true, &entry
	}

	// Check CIDR ranges
	rows, err := i.db.Pool.Query(ctx,
		`SELECT id, ip_address, cidr, reason, threat_type, source, permanent, blocked_until, created_at, updated_at, report_count
		 FROM ip_blocklist
		 WHERE cidr IS NOT NULL AND (permanent = true OR blocked_until > NOW())`)
	if err != nil {
		return false, nil
	}
	defer rows.Close()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, nil
	}

	for rows.Next() {
		var e IPBlocklistEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.CIDR, &e.Reason, &e.ThreatType,
			&e.Source, &e.Permanent, &e.BlockedUntil, &e.CreatedAt, &e.UpdatedAt, &e.ReportCount); err != nil {
			continue
		}

		if e.CIDR != "" {
			_, ipNet, err := net.ParseCIDR(e.CIDR)
			if err == nil && ipNet.Contains(parsedIP) {
				return true, &e
			}
		}
	}

	return false, nil
}

// CheckAllowlist checks if an IP is on the allowlist
func (i *IPIntelligence) CheckAllowlist(ctx context.Context, ip string) (bool, *IPAllowlistEntry) {
	// Check exact match first
	var entry IPAllowlistEntry
	err := i.db.Pool.QueryRow(ctx,
		`SELECT id, ip_address, cidr, label, created_at FROM ip_allowlist WHERE ip_address = $1`,
		ip).Scan(&entry.ID, &entry.IPAddress, &entry.CIDR, &entry.Label, &entry.CreatedAt)

	if err == nil {
		return true, &entry
	}

	// Check CIDR ranges
	rows, err := i.db.Pool.Query(ctx,
		`SELECT id, ip_address, cidr, label, created_at FROM ip_allowlist WHERE cidr IS NOT NULL`)
	if err != nil {
		return false, nil
	}
	defer rows.Close()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, nil
	}

	for rows.Next() {
		var e IPAllowlistEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.CIDR, &e.Label, &e.CreatedAt); err != nil {
			continue
		}

		if e.CIDR != "" {
			_, ipNet, err := net.ParseCIDR(e.CIDR)
			if err == nil && ipNet.Contains(parsedIP) {
				return true, &e
			}
		}
	}

	return false, nil
}

// AddToBlocklist adds an IP address or range to the blocklist
func (i *IPIntelligence) AddToBlocklist(ctx context.Context, ip, reason, threatType, source string, permanent bool, blockedUntil *time.Time) error {
	cidr := ""
	if strings.Contains(ip, "/") {
		cidr = ip
	}

	_, err := i.db.Pool.Exec(ctx,
		`INSERT INTO ip_blocklist (ip_address, cidr, reason, threat_type, source, permanent, blocked_until, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		 ON CONFLICT (ip_address) DO UPDATE
		 SET reason = EXCLUDED.reason,
		     threat_type = EXCLUDED.threat_type,
		     source = EXCLUDED.source,
		     permanent = EXCLUDED.permanent,
		     blocked_until = EXCLUDED.blocked_until,
		     updated_at = NOW(),
		     report_count = ip_blocklist.report_count + 1`,
		ip, cidr, reason, threatType, source, permanent, blockedUntil)

	if err != nil {
		return fmt.Errorf("failed to add to blocklist: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("geoip:%s", ip)
	i.redis.Client.Del(ctx, cacheKey)

	i.logger.Info("IP added to blocklist",
		zap.String("ip", ip),
		zap.String("threat_type", threatType),
		zap.String("reason", reason),
	)

	return nil
}

// RemoveFromBlocklist removes an IP from the blocklist
func (i *IPIntelligence) RemoveFromBlocklist(ctx context.Context, ip string) error {
	_, err := i.db.Pool.Exec(ctx,
		`DELETE FROM ip_blocklist WHERE ip_address = $1`, ip)

	if err != nil {
		return fmt.Errorf("failed to remove from blocklist: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("geoip:%s", ip)
	i.redis.Client.Del(ctx, cacheKey)

	i.logger.Info("IP removed from blocklist", zap.String("ip", ip))

	return nil
}

// AddToAllowlist adds an IP address or range to the allowlist
func (i *IPIntelligence) AddToAllowlist(ctx context.Context, ip, label string) error {
	cidr := ""
	if strings.Contains(ip, "/") {
		cidr = ip
	}

	_, err := i.db.Pool.Exec(ctx,
		`INSERT INTO ip_allowlist (ip_address, cidr, label, created_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (ip_address) DO UPDATE SET label = EXCLUDED.label`,
		ip, cidr, label)

	if err != nil {
		return fmt.Errorf("failed to add to allowlist: %w", err)
	}

	i.logger.Info("IP added to allowlist",
		zap.String("ip", ip),
		zap.String("label", label),
	)

	return nil
}

// RemoveFromAllowlist removes an IP from the allowlist
func (i *IPIntelligence) RemoveFromAllowlist(ctx context.Context, ip string) error {
	_, err := i.db.Pool.Exec(ctx,
		`DELETE FROM ip_allowlist WHERE ip_address = $1`, ip)

	if err != nil {
		return fmt.Errorf("failed to remove from allowlist: %w", err)
	}

	i.logger.Info("IP removed from allowlist", zap.String("ip", ip))

	return nil
}

// CheckImpossibleTravel detects impossible travel between two login locations
func (i *IPIntelligence) CheckImpossibleTravel(ctx context.Context, userID string, currentIP string, currentTime time.Time) (*ImpossibleTravelResult, error) {
	result := &ImpossibleTravelResult{
		CurrentTime: currentTime,
	}

	// Get last successful login for this user
	var lastIP string
	var lastLat, lastLon float64
	var lastTime time.Time

	err := i.db.Pool.QueryRow(ctx,
		`SELECT ip_address, latitude, longitude, created_at
		 FROM login_history
		 WHERE user_id = $1 AND success = true AND latitude != 0 AND longitude != 0
		 ORDER BY created_at DESC LIMIT 1`,
		userID).Scan(&lastIP, &lastLat, &lastLon, &lastTime)

	if err != nil {
		// No previous login - can't check impossible travel
		result.IsImpossible = false
		return result, nil
	}

	result.PreviousLocation = &GeoPoint{
		Latitude:  lastLat,
		Longitude: lastLon,
	}
	result.PreviousTime = lastTime

	// Get current location
	geoResult, err := i.LookupGeoIP(ctx, currentIP)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup current IP: %w", err)
	}

	result.CurrentLocation = &GeoPoint{
		Latitude:  geoResult.Latitude,
		Longitude: geoResult.Longitude,
		Country:   geoResult.Country,
		City:      geoResult.City,
	}

	// Calculate distance
	result.DistanceKm = haversineDistance(
		lastLat, lastLon,
		geoResult.Latitude, geoResult.Longitude,
	)

	// Calculate time delta
	result.TimeDelta = currentTime.Sub(lastTime)

	// Skip check if distance is too small or time delta is negative
	if result.DistanceKm < i.config.MinDistanceCheck || result.TimeDelta <= 0 {
		result.IsImpossible = false
		return result, nil
	}

	// Calculate minimum travel time
	result.RequiredTime = time.Duration(result.DistanceKm/i.config.MaxTravelSpeed) * time.Hour

	// Check if travel is impossible
	if result.TimeDelta < result.RequiredTime {
		result.IsImpossible = true
		result.SpeedKmh = result.DistanceKm / result.TimeDelta.Hours()

		i.logger.Warn("Impossible travel detected",
			zap.String("user_id", userID),
			zap.Float64("distance_km", result.DistanceKm),
			zap.Duration("time_delta", result.TimeDelta),
			zap.Float64("speed_kmh", result.SpeedKmh),
		)
	}

	return result, nil
}

// GetThreatScore returns a threat score for an IP based on various factors
func (i *IPIntelligence) GetThreatScore(ctx context.Context, ip string) (int, error) {
	score := 0

	// Check blocklist
	blocked, entry := i.CheckBlocklist(ctx, ip)
	if blocked {
		if entry.ThreatType == "malware" || entry.ThreatType == "botnet" {
			score = 100
		} else {
			score = 70
		}
		return score, nil
	}

	// Check allowlist (reduces score)
	allowlisted, _ := i.CheckAllowlist(ctx, ip)
	if allowlisted {
		return 0, nil
	}

	// Get GeoIP info
	geoResult, err := i.LookupGeoIP(ctx, ip)
	if err == nil {
		// Check for Tor
		if geoResult.IsTor {
			score = 60
		}

		// Check for VPN
		if geoResult.IsVPN {
			score = maxIPInt(score, 30)
		}

		// Check for proxy
		if geoResult.IsProxy {
			score = maxIPInt(score, 40)
		}

		// Check for hosting
		if geoResult.IsHosting {
			score = maxIPInt(score, 20)
		}
	}

	// Check for recent failed login attempts from this IP
	var failCount int
	err = i.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE ip_address = $1 AND success = false AND created_at > NOW() - INTERVAL '1 hour'`,
		ip).Scan(&failCount)
	if err == nil && failCount > 5 {
		score += minIPInt(30, failCount*5)
	}

	return minIPInt(score, 100), nil
}

// ListBlocklistEntries returns all entries on the blocklist
func (i *IPIntelligence) ListBlocklistEntries(ctx context.Context, limit, offset int) ([]IPBlocklistEntry, int, error) {
	var total int
	err := i.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_blocklist`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := i.db.Pool.Query(ctx,
		`SELECT id, ip_address, cidr, reason, threat_type, source, permanent, blocked_until, created_at, updated_at, report_count
		 FROM ip_blocklist
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []IPBlocklistEntry
	for rows.Next() {
		var e IPBlocklistEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.CIDR, &e.Reason, &e.ThreatType,
			&e.Source, &e.Permanent, &e.BlockedUntil, &e.CreatedAt, &e.UpdatedAt, &e.ReportCount); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}

// ListAllowlistEntries returns all entries on the allowlist
func (i *IPIntelligence) ListAllowlistEntries(ctx context.Context, limit, offset int) ([]IPAllowlistEntry, int, error) {
	var total int
	err := i.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_allowlist`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := i.db.Pool.Query(ctx,
		`SELECT id, ip_address, cidr, label, created_at
		 FROM ip_allowlist
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []IPAllowlistEntry
	for rows.Next() {
		var e IPAllowlistEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.CIDR, &e.Label, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}

// Helper functions

// max returns the maximum of two integers
func maxIP(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func minIP(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxIPInt is a wrapper for compatibility
func maxIPInt(a, b int) int {
	return maxIP(a, b)
}

// minIPInt is a wrapper for compatibility
func minIPInt(a, b int) int {
	return minIP(a, b)
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
