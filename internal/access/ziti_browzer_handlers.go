// Package access - HTTP handlers for BrowZer management API
package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// handleBrowZerStatus returns the current BrowZer configuration state
func (s *Service) handleBrowZerStatus(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"reason":  "ziti not initialized",
		})
		return
	}

	cfg, err := s.zitiManager.GetBrowZerConfig(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":           false,
			"configured":        false,
			"bootstrapper_url":  "http://localhost:1408",
		})
		return
	}

	c.JSON(http.StatusOK, cfg)
}

// handleEnableBrowZer creates all BrowZer resources on the Ziti controller
func (s *Service) handleEnableBrowZer(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti not initialized"})
		return
	}

	err := s.zitiManager.BootstrapBrowZer(
		c.Request.Context(),
		s.oauthIssuer,
		s.oauthJWKSURL,
		s.config.BrowZerClientID,
	)
	if err != nil {
		s.logger.Error("Failed to enable BrowZer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "BrowZer enabled"})
}

// handleDisableBrowZer removes BrowZer resources from the Ziti controller
func (s *Service) handleDisableBrowZer(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti not initialized"})
		return
	}

	err := s.zitiManager.DisableBrowZer(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to disable BrowZer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "BrowZer disabled"})
}

// handleEnableBrowZerOnService adds the "browzer-enabled" role attribute to a Ziti service
func (s *Service) handleEnableBrowZerOnService(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti not initialized"})
		return
	}

	zitiServiceID := c.Param("id")

	// Get current attributes
	attrs, err := s.zitiManager.GetServiceRoleAttributes(c.Request.Context(), zitiServiceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found"})
		return
	}

	// Add browzer-enabled if not present
	hasBrowzer := false
	for _, a := range attrs {
		if a == "browzer-enabled" {
			hasBrowzer = true
			break
		}
	}
	if !hasBrowzer {
		attrs = append(attrs, "browzer-enabled")
	}

	if err := s.zitiManager.PatchServiceRoleAttributes(c.Request.Context(), zitiServiceID, attrs); err != nil {
		s.logger.Error("Failed to enable BrowZer on service", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "BrowZer enabled on service", "role_attributes": attrs})
}

// handleDisableBrowZerOnService removes the "browzer-enabled" role attribute from a Ziti service
func (s *Service) handleDisableBrowZerOnService(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti not initialized"})
		return
	}

	zitiServiceID := c.Param("id")

	attrs, err := s.zitiManager.GetServiceRoleAttributes(c.Request.Context(), zitiServiceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found"})
		return
	}

	// Remove browzer-enabled
	filtered := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if a != "browzer-enabled" {
			filtered = append(filtered, a)
		}
	}

	if err := s.zitiManager.PatchServiceRoleAttributes(c.Request.Context(), zitiServiceID, filtered); err != nil {
		s.logger.Error("Failed to disable BrowZer on service", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "BrowZer disabled on service", "role_attributes": filtered})
}
