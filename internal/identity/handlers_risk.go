package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/risk"
)

// handleListRiskPolicies returns all risk policies
func (s *Service) handleListRiskPolicies(c *gin.Context) {
	enabledOnly := c.Query("enabled_only") == "true"

	policies, err := s.risk.ListRiskPolicies(c.Request.Context(), enabledOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// handleGetRiskPolicy returns a specific risk policy
func (s *Service) handleGetRiskPolicy(c *gin.Context) {
	policyID := c.Param("id")

	policy, err := s.risk.GetRiskPolicy(c.Request.Context(), policyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// handleCreateRiskPolicy creates a new risk policy
func (s *Service) handleCreateRiskPolicy(c *gin.Context) {
	var req risk.CreateRiskPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := s.risk.CreateRiskPolicy(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// handleUpdateRiskPolicy updates an existing risk policy
func (s *Service) handleUpdateRiskPolicy(c *gin.Context) {
	policyID := c.Param("id")

	var req risk.CreateRiskPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := s.risk.UpdateRiskPolicy(c.Request.Context(), policyID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// handleDeleteRiskPolicy deletes a risk policy
func (s *Service) handleDeleteRiskPolicy(c *gin.Context) {
	policyID := c.Param("id")

	if err := s.risk.DeleteRiskPolicy(c.Request.Context(), policyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// handleToggleRiskPolicy enables or disables a risk policy
func (s *Service) handleToggleRiskPolicy(c *gin.Context) {
	policyID := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.risk.ToggleRiskPolicy(c.Request.Context(), policyID, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy updated", "enabled": req.Enabled})
}

// handleEvaluateRisk evaluates risk for a given context (testing endpoint)
func (s *Service) handleEvaluateRisk(c *gin.Context) {
	var req struct {
		UserID      string `json:"user_id" binding:"required"`
		IPAddress   string `json:"ip_address" binding:"required"`
		UserAgent   string `json:"user_agent"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get geo info
	geoResult, _ := s.risk.GeoIPLookup(c.Request.Context(), req.IPAddress)
	location := ""
	var lat, lon float64
	country := ""
	if geoResult != nil {
		location = geoResult.City + ", " + geoResult.Country
		lat = geoResult.Lat
		lon = geoResult.Lon
		country = geoResult.CountryCode
	}

	// Compute fingerprint if not provided
	fingerprint := req.Fingerprint
	if fingerprint == "" {
		fingerprint = s.risk.ComputeDeviceFingerprint(req.IPAddress, req.UserAgent)
	}

	// Check if device is new/trusted
	_, isNew, _ := s.risk.RegisterDevice(c.Request.Context(), req.UserID, fingerprint, req.IPAddress, req.UserAgent, location)
	isTrusted := s.risk.IsDeviceTrusted(c.Request.Context(), req.UserID, fingerprint)

	// Get failed attempts
	failedAttempts := s.risk.GetRecentFailedAttempts(c.Request.Context(), req.UserID)

	// Get user groups
	var groups []string
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT g.name FROM groups g
		 JOIN user_groups ug ON g.id = ug.group_id
		 WHERE ug.user_id = $1`, req.UserID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				groups = append(groups, name)
			}
		}
	}

	// Evaluate policies
	loginCtx := risk.EvaluateLoginContext{
		UserID:            req.UserID,
		IPAddress:         req.IPAddress,
		UserAgent:         req.UserAgent,
		DeviceFingerprint: fingerprint,
		Location:          location,
		Latitude:          lat,
		Longitude:         lon,
		Country:           country,
		IsNewDevice:       isNew,
		IsDeviceTrusted:   isTrusted,
		FailedAttempts:    failedAttempts,
		UserGroups:        groups,
	}

	result, err := s.risk.EvaluateRiskPolicies(c.Request.Context(), loginCtx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"evaluation": result,
		"context": gin.H{
			"is_new_device":   isNew,
			"is_trusted":      isTrusted,
			"failed_attempts": failedAttempts,
			"location":        location,
			"country":         country,
			"user_groups":     groups,
		},
	})
}

// handleGetRiskStats returns risk statistics for the dashboard
func (s *Service) handleGetRiskStats(c *gin.Context) {
	stats, err := s.risk.GetRiskStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// handleGetLoginHistory returns login history for a user or all users
func (s *Service) handleGetLoginHistory(c *gin.Context) {
	userID := c.Query("user_id")
	limit := 100

	history, err := s.risk.GetLoginHistory(c.Request.Context(), userID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}
