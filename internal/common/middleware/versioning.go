// Package middleware provides API versioning middleware for OpenIDX services
package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// API versioning constants
const (
	// ContextAPIVersion is the context key where the resolved API version is stored
	ContextAPIVersion = "api_version"

	// HeaderAPIVersion is the response header containing the API version
	HeaderAPIVersion = "X-API-Version"

	// HeaderAPIVersionRequest is the request header for explicit version selection
	HeaderAPIVersionRequest = "API-Version"

	// HeaderDeprecation is the deprecation warning header
	HeaderDeprecation = "Deprecation"

	// HeaderSunset is the sunset date header
	HeaderSunset = "Sunset"

	// HeaderAlternateVersions is the header listing available versions
	HeaderAlternateVersions = "X-API-Versions"
)

// VersionConfig holds the configuration for API versioning
type VersionConfig struct {
	// Supported versions (e.g., ["v1", "v2"])
	Supported []string

	// Default version if none is specified
	Default string

	// Deprecated versions with their sunset dates
	Deprecated map[string]string // version -> sunset date (RFC 3339)

	// Latest version (for migration hints)
	Latest string
}

// DefaultVersionConfig returns the default version configuration
func DefaultVersionConfig() *VersionConfig {
	return &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    "v1",
		Deprecated: map[string]string{"v1": "2027-12-31"}, // v1 deprecated, sunset end of 2027
		Latest:     "v2",
	}
}

// APIVersion creates a middleware that handles API versioning via:
// 1. URL path (/api/v1/, /api/v2/)
// 2. API-Version header
// 3. Accept header (application/vnd.openidx.v2+json)
func APIVersion(defaultVersion string) gin.HandlerFunc {
	cfg := &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    defaultVersion,
		Deprecated: map[string]string{"v1": "2027-12-31"},
		Latest:     "v2",
	}
	return APIVersionWithConfig(cfg)
}

// APIVersionWithConfig creates a versioning middleware with custom configuration
func APIVersionWithConfig(cfg *VersionConfig) gin.HandlerFunc {
	// Build deprecation lookup
	deprecatedVersions := make(map[string]bool)
	sunsetDates := make(map[string]string)
	for v, sunset := range cfg.Deprecated {
		deprecatedVersions[v] = true
		sunsetDates[v] = sunset
	}

	// Build supported versions set
	supportedSet := make(map[string]bool)
	for _, v := range cfg.Supported {
		supportedSet[v] = true
	}

	return func(c *gin.Context) {
		version := cfg.Default

		// 1. Try URL path versioning (/api/v1/, /api/v2/)
		if urlVersion := extractVersionFromPath(c.Request.URL.Path); urlVersion != "" {
			version = urlVersion
		} else {
			// 2. Try API-Version header
			if headerVersion := c.GetHeader(HeaderAPIVersionRequest); headerVersion != "" {
				// Normalize version (add 'v' prefix if needed)
				normalized := normalizeVersion(headerVersion)
				if supportedSet[normalized] {
					version = normalized
				} else {
					// Unsupported version requested
					c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{
						"error":   "unsupported_api_version",
						"message": fmt.Sprintf("API version %s is not supported", headerVersion),
						"supported_versions": cfg.Supported,
						"default_version":    cfg.Default,
					})
					return
				}
			} else {
				// 3. Try Accept header (application/vnd.openidx.v2+json)
				if acceptVersion := extractVersionFromAccept(c.GetHeader("Accept")); acceptVersion != "" {
					if supportedSet[acceptVersion] {
						version = acceptVersion
					}
				}
			}
		}

		// Final validation
		normalizedVersion := normalizeVersion(version)
		if !supportedSet[normalizedVersion] {
			c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{
				"error":   "unsupported_api_version",
				"message": fmt.Sprintf("API version %s is not supported", version),
				"supported_versions": cfg.Supported,
				"default_version":    cfg.Default,
			})
			return
		}

		// Store version in context
		c.Set(ContextAPIVersion, normalizedVersion)

		// Set response headers
		SetAPIVersionHeaders(c, normalizedVersion, deprecatedVersions[normalizedVersion])

		// Add sunset header if deprecated
		if sunsetDate, ok := sunsetDates[normalizedVersion]; ok {
			c.Header(HeaderSunset, formatSunsetDate(sunsetDate))
		}

		// Add hint for latest version if using older version
		if normalizedVersion != cfg.Latest {
			c.Header("X-API-Latest-Version", cfg.Latest)
		}

		c.Next()
	}
}

// ParseAPIVersion extracts the API version from the gin context
func ParseAPIVersion(c *gin.Context) string {
	if v, exists := c.Get(ContextAPIVersion); exists {
		if version, ok := v.(string); ok {
			return version
		}
	}
	return "v1" // Default fallback
}

// SetAPIVersionHeaders sets the standard API versioning headers
func SetAPIVersionHeaders(c *gin.Context, version string, deprecated bool) {
	// Set the current API version
	c.Header(HeaderAPIVersion, version)

	// Set deprecation warning if applicable
	if deprecated {
		c.Header(HeaderDeprecation, "true")
		c.Header("Warning", fmt.Sprintf(`299 - "%s is deprecated"`, version))
	}

	// List all available versions
	c.Header(HeaderAlternateVersions, strings.Join([]string{"v1", "v2"}, ", "))
}

// VersionRouteGroup creates a versioned route group with the proper prefix
func VersionRouteGroup(router *gin.Engine, version string) *gin.RouterGroup {
	normalized := normalizeVersion(version)
	return router.Group("/api/" + normalized)
}

// extractVersionFromPath extracts the version from the URL path
// Handles patterns like /api/v1/, /api/v2/, /api/v1/users
func extractVersionFromPath(path string) string {
	// Regex to match /api/v{digits}/ or /api/v{digits}
	re := regexp.MustCompile(`^/api/v(\d+)(?:/|$)`)
	matches := re.FindStringSubmatch(path)
	if len(matches) >= 2 {
		return "v" + matches[1]
	}
	return ""
}

// extractVersionFromAccept extracts version from Accept header
// Handles patterns like application/vnd.openidx.v2+json
func extractVersionFromAccept(accept string) string {
	if accept == "" {
		return ""
	}

	// Pattern: application/vnd.openidx.v{digits}+json
	re := regexp.MustCompile(`application/vnd\.openidx\.v(\d+)(?:\+json)?`)
	matches := re.FindStringSubmatch(accept)
	if len(matches) >= 2 {
		return "v" + matches[1]
	}

	// Pattern: application/vnd.api.v{digits}+json
	re2 := regexp.MustCompile(`application/vnd\.api\.v(\d+)(?:\+json)?`)
	matches2 := re2.FindStringSubmatch(accept)
	if len(matches2) >= 2 {
		return "v" + matches2[1]
	}

	return ""
}

// normalizeVersion ensures version has 'v' prefix
func normalizeVersion(version string) string {
	if version == "" {
		return "v1"
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	// Check if it's just a number
	if _, err := strconv.Atoi(version); err == nil {
		return "v" + version
	}
	return version
}

// formatSunsetDate formats a sunset date string to RFC 1123 (HTTP date format)
func formatSunsetDate(dateStr string) string {
	// Try to parse common date formats
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t.UTC().Format(time.RFC1123)
		}
	}

	// Return as-is if parsing fails
	return dateStr
}

// VersionConstraint creates a middleware that only allows requests
// matching the specified version constraints
func VersionConstraint(constraint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		version := ParseAPIVersion(c)

		// Support constraints like ">=v1", "v2", "!v1"
		if !matchesConstraint(version, constraint) {
			c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{
				"error":   "version_constraint_not_met",
				"message": fmt.Sprintf("API version %s does not match constraint: %s", version, constraint),
				"current_version": version,
				"constraint":      constraint,
			})
			return
		}

		c.Next()
	}
}

// matchesConstraint checks if a version matches a constraint string
func matchesConstraint(version, constraint string) bool {
	normalized := normalizeVersion(version)

	switch {
	case strings.HasPrefix(constraint, ">="):
		minVersion := normalizeVersion(strings.TrimPrefix(constraint, ">="))
		return compareVersions(normalized, minVersion) >= 0

	case strings.HasPrefix(constraint, "<="):
		maxVersion := normalizeVersion(strings.TrimPrefix(constraint, "<="))
		return compareVersions(normalized, maxVersion) <= 0

	case strings.HasPrefix(constraint, ">"):
		minVersion := normalizeVersion(strings.TrimPrefix(constraint, ">"))
		return compareVersions(normalized, minVersion) > 0

	case strings.HasPrefix(constraint, "<"):
		maxVersion := normalizeVersion(strings.TrimPrefix(constraint, "<"))
		return compareVersions(normalized, maxVersion) < 0

	case strings.HasPrefix(constraint, "!"):
		excluded := normalizeVersion(strings.TrimPrefix(constraint, "!"))
		return normalized != excluded

	case strings.Contains(constraint, "||"):
		// OR constraint: v1 || v2
		versions := strings.Split(constraint, "||")
		for _, v := range versions {
			if matchesConstraint(version, strings.TrimSpace(v)) {
				return true
			}
		}
		return false

	default:
		// Exact match
		return normalized == normalizeVersion(constraint)
	}
}

// compareVersions compares two version strings (v1, v2, etc.)
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Extract version numbers
	num1 := extractVersionNumber(v1)
	num2 := extractVersionNumber(v2)

	switch {
	case num1 < num2:
		return -1
	case num1 > num2:
		return 1
	default:
		return 0
	}
}

// extractVersionNumber extracts the numeric part from a version string
func extractVersionNumber(version string) int {
	re := regexp.MustCompile(`v?(\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) >= 2 {
		num, _ := strconv.Atoi(matches[1])
		return num
	}
	return 0
}

// VersionResponse wraps response data with version metadata
type VersionResponse struct {
	Data     interface{} `json:"data"`
	Meta     Meta        `json:"meta,omitempty"`
	Links    Links       `json:"links,omitempty"`
}

// Meta contains response metadata
type Meta struct {
	Version      string `json:"api_version"`
	Deprecated   bool   `json:"deprecated,omitempty"`
	SunsetDate   string `json:"sunset_date,omitempty"`
	Latest       string `json:"latest_version,omitempty"`
}

// Links contains related links
type Links struct {
	Self         string `json:"self,omitempty"`
	Current      string `json:"current_version,omitempty"`
	NextVersion  string `json:"next_version,omitempty"`
}

// WrapVersionedResponse wraps response data with version metadata
func WrapVersionedResponse(c *gin.Context, data interface{}) VersionResponse {
	version := ParseAPIVersion(c)

	meta := Meta{
		Version: version,
	}

	// Check if deprecated (read from response headers, not request headers)
	if c.Writer.Header().Get(HeaderDeprecation) == "true" {
		meta.Deprecated = true
		meta.SunsetDate = c.Writer.Header().Get(HeaderSunset)
	}

	// Add latest version info
	if latest := c.Writer.Header().Get("X-API-Latest-Version"); latest != "" {
		meta.Latest = latest
	}

	return VersionResponse{
		Data: data,
		Meta: meta,
	}
}

// VersionedRoute creates a route that only responds to a specific API version
func VersionedRoute(versions ...string) gin.HandlerFunc {
	normalizedVersions := make(map[string]bool)
	for _, v := range versions {
		normalizedVersions[normalizeVersion(v)] = true
	}

	return func(c *gin.Context) {
		currentVersion := ParseAPIVersion(c)
		if !normalizedVersions[currentVersion] {
			c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{
				"error":   "unsupported_version_for_endpoint",
				"message": fmt.Sprintf("This endpoint is available in API versions: %v", versions),
				"current_version": currentVersion,
				"supported_versions": versions,
			})
			return
		}
		c.Next()
	}
}

// MigrateVersion creates middleware that handles version migration logic
// It can transform requests from old versions to new version format
func MigrateVersion(fromVersion, toVersion string, migrator func(*gin.Context) error) gin.HandlerFunc {
	fromNormalized := normalizeVersion(fromVersion)
	toNormalized := normalizeVersion(toVersion)

	return func(c *gin.Context) {
		version := ParseAPIVersion(c)

		if version == fromNormalized {
			// Run migration transformation
			if err := migrator(c); err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":   "version_migration_failed",
					"message": err.Error(),
				})
				return
			}
			// Update context version to target
			c.Set(ContextAPIVersion, toNormalized)
		}

		c.Next()
	}
}
