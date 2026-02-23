// Package api provides API versioning and negotiation for OpenIDX services
package api

import (
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// HeaderAPIVersion is the response header that contains the API version
	HeaderAPIVersion = "X-API-Version"

	// HeaderAPIVersionRequest is the request header for API version negotiation
	HeaderAPIVersionRequest = "X-API-Version"

	// DefaultAPIVersion is the default API version if none is specified
	DefaultAPIVersion = "1.0"
)

// VersionInfo holds API version information
type VersionInfo struct {
	Version   string
	Supported []string
}

// VersionMiddleware creates middleware that adds X-API-Version header to responses
// and optionally handles version negotiation
func VersionMiddleware(version string, supported []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add version header to response
		c.Header(HeaderAPIVersion, version)

		// Handle version negotiation if client specifies a version
		if requestedVersion := c.GetHeader(HeaderAPIVersionRequest); requestedVersion != "" {
			if !isVersionSupported(requestedVersion, supported) {
				c.Abort()
				c.JSON(406, gin.H{
					"error":   "unsupported_api_version",
					"message": "Requested API version is not supported",
					"supported_versions": supported,
				})
				return
			}
			// Store the negotiated version in context
			c.Set("api_version", requestedVersion)
		} else {
			// Store default version
			c.Set("api_version", version)
		}

		c.Next()
	}
}

// isVersionSupported checks if a version is in the supported list
func isVersionSupported(version string, supported []string) bool {
	// Support both "1" and "1.0" style versions
	for _, v := range supported {
		if v == version || strings.HasPrefix(v, version+".") {
			return true
		}
	}
	return false
}

// GetVersion extracts the API version from the gin context
func GetVersion(c *gin.Context) string {
	if v, exists := c.Get("api_version"); exists {
		if version, ok := v.(string); ok {
			return version
		}
	}
	return DefaultAPIVersion
}

// VersionRouteGroup creates a route group with the version prefix
// e.g., "/api/v1" for version 1
func VersionRouteGroup(router *gin.Engine, version string) *gin.RouterGroup {
	prefix := "/api/v" + strings.TrimPrefix(version, "v")
	return router.Group(prefix)
}

// VersionNegotiationMiddleware provides content negotiation based on Accept header
// for different response formats (JSON, YAML, XML, etc.)
type VersionNegotiationMiddleware struct {
	version   string
	supported []string
}

// NewVersionNegotiationMiddleware creates a new version negotiation middleware
func NewVersionNegotiationMiddleware(version string, supported []string) *VersionNegotiationMiddleware {
	return &VersionNegotiationMiddleware{
		version:   version,
		supported: supported,
	}
}

// Handler returns the gin handler function
func (m *VersionNegotiationMiddleware) Handler() gin.HandlerFunc {
	return VersionMiddleware(m.version, m.supported)
}

// WithVersion is a helper to add versioning to an existing router group
func WithVersion(group *gin.RouterGroup, version string, supported []string) *gin.RouterGroup {
	group.Use(VersionMiddleware(version, supported))
	return group
}

// StandardVersionMiddleware returns a middleware for the standard v1 API
func StandardVersionMiddleware() gin.HandlerFunc {
	return VersionMiddleware("1.0", []string{"1.0", "1"})
}

// V2VersionMiddleware returns a middleware for API v2 (future use)
func V2VersionMiddleware() gin.HandlerFunc {
	return VersionMiddleware("2.0", []string{"2.0", "2"})
}
