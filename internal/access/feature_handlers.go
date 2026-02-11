// Package access provides feature management API handlers
package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// FeatureEnableRequest represents the request to enable a feature
type FeatureEnableRequest struct {
	// Ziti config
	ZitiServiceName string `json:"ziti_service_name,omitempty"`
	ZitiHost        string `json:"ziti_host,omitempty"`
	ZitiPort        int    `json:"ziti_port,omitempty"`

	// Guacamole config
	GuacamoleProtocol string `json:"guacamole_protocol,omitempty"`
	GuacamoleHost     string `json:"guacamole_host,omitempty"`
	GuacamolePort     int    `json:"guacamole_port,omitempty"`
	GuacamoleUsername string `json:"guacamole_username,omitempty"`
	GuacamolePassword string `json:"guacamole_password,omitempty"`
}

// handleGetServiceFeatures returns all features for a service
func (s *Service) handleGetServiceFeatures(c *gin.Context) {
	routeID := c.Param("id")

	if s.featureManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "feature manager not initialized"})
		return
	}

	status, err := s.featureManager.GetServiceStatus(c.Request.Context(), routeID)
	if err != nil {
		s.logger.Error("Failed to get service features", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// handleGetServiceStatus returns the status of a specific service
func (s *Service) handleGetServiceStatus(c *gin.Context) {
	routeID := c.Param("id")

	if s.featureManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "feature manager not initialized"})
		return
	}

	status, err := s.featureManager.GetServiceStatus(c.Request.Context(), routeID)
	if err != nil {
		s.logger.Error("Failed to get service status", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// handleEnableZitiFeature enables Ziti on a service
func (s *Service) handleEnableZitiFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.enableFeature(c, routeID, FeatureZiti)
}

// handleDisableZitiFeature disables Ziti on a service
func (s *Service) handleDisableZitiFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.disableFeature(c, routeID, FeatureZiti)
}

// handleEnableBrowZerFeature enables BrowZer on a service
func (s *Service) handleEnableBrowZerFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.enableFeature(c, routeID, FeatureBrowZer)
}

// handleDisableBrowZerFeature disables BrowZer on a service
func (s *Service) handleDisableBrowZerFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.disableFeature(c, routeID, FeatureBrowZer)
}

// handleEnableGuacamoleFeature enables Guacamole on a service
func (s *Service) handleEnableGuacamoleFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.enableFeature(c, routeID, FeatureGuacamole)
}

// handleDisableGuacamoleFeature disables Guacamole on a service
func (s *Service) handleDisableGuacamoleFeature(c *gin.Context) {
	routeID := c.Param("id")
	s.disableFeature(c, routeID, FeatureGuacamole)
}

func (s *Service) enableFeature(c *gin.Context, routeID string, feature FeatureName) {
	if s.featureManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "feature manager not initialized"})
		return
	}

	var req FeatureEnableRequest
	if err := c.ShouldBindJSON(&req); err != nil && c.Request.ContentLength > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := &FeatureConfig{
		ZitiServiceName:   req.ZitiServiceName,
		ZitiHost:          req.ZitiHost,
		ZitiPort:          req.ZitiPort,
		GuacamoleProtocol: req.GuacamoleProtocol,
		GuacamoleHost:     req.GuacamoleHost,
		GuacamolePort:     req.GuacamolePort,
		GuacamoleUsername: req.GuacamoleUsername,
		GuacamolePassword: req.GuacamolePassword,
	}

	// Get user ID from context (set by auth middleware)
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	err := s.featureManager.EnableFeature(c.Request.Context(), routeID, feature, config, userID)
	if err != nil {
		s.logger.Error("Failed to enable feature",
			zap.String("route_id", routeID),
			zap.String("feature", string(feature)),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Log audit event
	s.logAuditEvent(c, "feature_enabled", routeID, "proxy_route", map[string]interface{}{
		"feature": string(feature),
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "feature enabled",
		"feature": string(feature),
	})
}

func (s *Service) disableFeature(c *gin.Context, routeID string, feature FeatureName) {
	if s.featureManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "feature manager not initialized"})
		return
	}

	err := s.featureManager.DisableFeature(c.Request.Context(), routeID, feature)
	if err != nil {
		s.logger.Error("Failed to disable feature",
			zap.String("route_id", routeID),
			zap.String("feature", string(feature)),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Log audit event
	s.logAuditEvent(c, "feature_disabled", routeID, "proxy_route", map[string]interface{}{
		"feature": string(feature),
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "feature disabled",
		"feature": string(feature),
	})
}

// handleGetAllServicesStatus returns status for all services
func (s *Service) handleGetAllServicesStatus(c *gin.Context) {
	if s.featureManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "feature manager not initialized"})
		return
	}

	// Get all routes
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id FROM proxy_routes WHERE enabled = true ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list routes"})
		return
	}
	defer rows.Close()

	var services []*ServiceStatus
	for rows.Next() {
		var routeID string
		if err := rows.Scan(&routeID); err != nil {
			continue
		}

		status, err := s.featureManager.GetServiceStatus(c.Request.Context(), routeID)
		if err != nil {
			continue
		}
		services = append(services, status)
	}

	c.JSON(http.StatusOK, gin.H{
		"services": services,
		"total":    len(services),
	})
}
