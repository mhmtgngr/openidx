// Package access - HTTP handlers for BrowZer management API
package access

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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
// and optionally creates a proxy_route for path-based BrowZer access.
func (s *Service) handleEnableBrowZerOnService(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti not initialized"})
		return
	}

	zitiServiceID := c.Param("id")

	// Parse optional path from request body
	var body struct {
		Path string `json:"path"`
	}
	_ = c.ShouldBindJSON(&body)
	browzerPath := strings.TrimSpace(body.Path)

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

	// If a path was provided, create/update a proxy_route for path-based BrowZer routing
	var routePath string
	if browzerPath != "" {
		if !strings.HasPrefix(browzerPath, "/") {
			browzerPath = "/" + browzerPath
		}
		routePath = browzerPath

		// Look up the service details from the database
		var serviceName, serviceHost string
		var servicePort int
		err := s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT name, host, port FROM ziti_services WHERE ziti_id = $1`, zitiServiceID,
		).Scan(&serviceName, &serviceHost, &servicePort)
		if err != nil {
			s.logger.Warn("Could not look up service details for BrowZer path route", zap.Error(err))
		} else {
			domain := "browzer.localtest.me"
			if s.browzerTargetManager != nil {
				if d := s.browzerTargetManager.GetDomain(); d != "" {
					domain = d
				}
			}

			fromURL := fmt.Sprintf("http://%s%s", domain, browzerPath)
			toURL := fmt.Sprintf("http://%s:%d", serviceHost, servicePort)
			routeName := fmt.Sprintf("browzer-%s", serviceName)

			// Delete any existing route for this service, then insert fresh
			_, _ = s.db.Pool.Exec(c.Request.Context(),
				`DELETE FROM proxy_routes WHERE ziti_service_name = $1 AND browzer_enabled = true`, serviceName)
			_, dbErr := s.db.Pool.Exec(c.Request.Context(),
				`INSERT INTO proxy_routes (name, description, from_url, to_url, require_auth, enabled, priority, ziti_enabled, ziti_service_name, browzer_enabled)
				 VALUES ($1, $2, $3, $4, true, true, 10, true, $5, true)`,
				routeName, fmt.Sprintf("BrowZer path route for %s", serviceName), fromURL, toURL, serviceName,
			)
			if dbErr != nil {
				s.logger.Warn("Failed to create BrowZer path route", zap.Error(dbErr))
			} else {
				s.logger.Info("Created BrowZer path route",
					zap.String("from", fromURL), zap.String("to", toURL), zap.String("service", serviceName))
			}
		}
	}

	// Regenerate BrowZer bootstrapper targets config
	if s.browzerTargetManager != nil {
		go s.browzerTargetManager.WriteBrowZerTargets(context.Background())
	}

	resp := gin.H{"message": "BrowZer enabled on service", "role_attributes": attrs}
	if routePath != "" {
		resp["browzer_path"] = routePath
	}
	c.JSON(http.StatusOK, resp)
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

	// Clean up any BrowZer proxy_route for this service
	var serviceName string
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT name FROM ziti_services WHERE ziti_id = $1`, zitiServiceID,
	).Scan(&serviceName); err == nil {
		_, _ = s.db.Pool.Exec(c.Request.Context(),
			`DELETE FROM proxy_routes WHERE ziti_service_name = $1 AND browzer_enabled = true`, serviceName)
	}

	// Regenerate BrowZer bootstrapper targets config
	if s.browzerTargetManager != nil {
		go s.browzerTargetManager.WriteBrowZerTargets(context.Background())
	}

	c.JSON(http.StatusOK, gin.H{"message": "BrowZer disabled on service", "role_attributes": filtered})
}
