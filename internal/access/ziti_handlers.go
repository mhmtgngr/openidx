// Package access - HTTP handlers for OpenZiti management endpoints
package access

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ---- Ziti Status ----

func (s *Service) handleZitiStatus(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":     false,
			"message":     "OpenZiti integration is not configured",
			"sdk_ready":   false,
		})
		return
	}

	status := gin.H{
		"enabled":   true,
		"sdk_ready": s.zitiManager.IsInitialized(),
	}

	// Check controller connectivity
	version, err := s.zitiManager.GetControllerVersion(c.Request.Context())
	if err != nil {
		status["controller_reachable"] = false
		status["controller_error"] = err.Error()
	} else {
		status["controller_reachable"] = true
		status["controller_version"] = version
	}

	// Count local DB records
	var serviceCount, identityCount int
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM ziti_services").Scan(&serviceCount)
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM ziti_identities").Scan(&identityCount)
	status["services_count"] = serviceCount
	status["identities_count"] = identityCount

	c.JSON(http.StatusOK, status)
}

// ---- Ziti Services ----

func (s *Service) handleListZitiServices(c *gin.Context) {
	// List from local DB
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, ziti_id, name, description, protocol, host, port, route_id, enabled, created_at, updated_at
		 FROM ziti_services ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ziti services"})
		return
	}
	defer rows.Close()

	type zitiServiceRow struct {
		ID          string    `json:"id"`
		ZitiID      string    `json:"ziti_id"`
		Name        string    `json:"name"`
		Description *string   `json:"description,omitempty"`
		Protocol    string    `json:"protocol"`
		Host        string    `json:"host"`
		Port        int       `json:"port"`
		RouteID     *string   `json:"route_id,omitempty"`
		Enabled     bool      `json:"enabled"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}

	services := []zitiServiceRow{}
	for rows.Next() {
		var svc zitiServiceRow
		err := rows.Scan(&svc.ID, &svc.ZitiID, &svc.Name, &svc.Description, &svc.Protocol,
			&svc.Host, &svc.Port, &svc.RouteID, &svc.Enabled, &svc.CreatedAt, &svc.UpdatedAt)
		if err != nil {
			s.logger.Error("Failed to scan ziti service", zap.Error(err))
			continue
		}
		services = append(services, svc)
	}

	c.JSON(http.StatusOK, gin.H{"services": services})
}

func (s *Service) handleCreateZitiService(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		Protocol    string   `json:"protocol"`
		Host        string   `json:"host" binding:"required"`
		Port        int      `json:"port" binding:"required"`
		Attributes  []string `json:"attributes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	attrs := req.Attributes
	if attrs == nil {
		attrs = []string{req.Name}
	}

	zitiID, err := s.zitiManager.CreateService(c.Request.Context(), req.Name, attrs)
	if err != nil {
		s.logger.Error("Failed to create ziti service", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Persist to DB
	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO ziti_services (ziti_id, name, description, protocol, host, port)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		zitiID, req.Name, req.Description, req.Protocol, req.Host, req.Port).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to persist ziti service to DB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "service created in Ziti but failed to persist locally"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"ziti_id": zitiID,
		"name":    req.Name,
		"message": "ziti service created",
	})
}

func (s *Service) handleDeleteZitiService(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	id := c.Param("id")

	// Get ziti_id from DB
	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id FROM ziti_services WHERE id=$1", id).Scan(&zitiID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti service not found"})
		return
	}

	// Delete from Ziti controller
	if err := s.zitiManager.DeleteService(c.Request.Context(), zitiID); err != nil {
		s.logger.Error("Failed to delete ziti service from controller", zap.Error(err))
		// Continue to delete from DB anyway
	}

	// Delete from DB
	s.db.Pool.Exec(c.Request.Context(), "DELETE FROM ziti_services WHERE id=$1", id)

	c.JSON(http.StatusOK, gin.H{"message": "ziti service deleted"})
}

// ---- Ziti Identities ----

func (s *Service) handleListZitiIdentities(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, ziti_id, name, identity_type, user_id, enrolled, attributes, created_at, updated_at
		 FROM ziti_identities ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ziti identities"})
		return
	}
	defer rows.Close()

	type zitiIdentityRow struct {
		ID           string    `json:"id"`
		ZitiID       string    `json:"ziti_id"`
		Name         string    `json:"name"`
		IdentityType string    `json:"identity_type"`
		UserID       *string   `json:"user_id,omitempty"`
		Enrolled     bool      `json:"enrolled"`
		Attributes   []string  `json:"attributes"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
	}

	identities := []zitiIdentityRow{}
	for rows.Next() {
		var ident zitiIdentityRow
		var attrs []byte
		err := rows.Scan(&ident.ID, &ident.ZitiID, &ident.Name, &ident.IdentityType,
			&ident.UserID, &ident.Enrolled, &attrs, &ident.CreatedAt, &ident.UpdatedAt)
		if err != nil {
			s.logger.Error("Failed to scan ziti identity", zap.Error(err))
			continue
		}
		json.Unmarshal(attrs, &ident.Attributes)
		identities = append(identities, ident)
	}

	c.JSON(http.StatusOK, gin.H{"identities": identities})
}

func (s *Service) handleCreateZitiIdentity(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	var req struct {
		Name         string   `json:"name" binding:"required"`
		IdentityType string   `json:"identity_type"`
		UserID       *string  `json:"user_id"`
		Attributes   []string `json:"attributes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.IdentityType == "" {
		req.IdentityType = "Device"
	}

	zitiID, enrollmentJWT, err := s.zitiManager.CreateIdentity(c.Request.Context(), req.Name, req.IdentityType, req.Attributes)
	if err != nil {
		s.logger.Error("Failed to create ziti identity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	attrsJSON, _ := json.Marshal(req.Attributes)

	// Persist to DB
	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrollment_jwt, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		zitiID, req.Name, req.IdentityType, req.UserID, enrollmentJWT, attrsJSON).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to persist ziti identity to DB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity created in Ziti but failed to persist locally"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":             id,
		"ziti_id":        zitiID,
		"name":           req.Name,
		"enrollment_jwt": enrollmentJWT,
		"message":        "ziti identity created",
	})
}

func (s *Service) handleDeleteZitiIdentity(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	id := c.Param("id")

	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id FROM ziti_identities WHERE id=$1", id).Scan(&zitiID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
		return
	}

	if err := s.zitiManager.DeleteIdentity(c.Request.Context(), zitiID); err != nil {
		s.logger.Error("Failed to delete ziti identity from controller", zap.Error(err))
	}

	s.db.Pool.Exec(c.Request.Context(), "DELETE FROM ziti_identities WHERE id=$1", id)

	c.JSON(http.StatusOK, gin.H{"message": "ziti identity deleted"})
}

func (s *Service) handleGetEnrollmentJWT(c *gin.Context) {
	id := c.Param("id")

	var enrollmentJWT *string
	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id, enrollment_jwt FROM ziti_identities WHERE id=$1", id).Scan(&zitiID, &enrollmentJWT)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
		return
	}

	if enrollmentJWT != nil && *enrollmentJWT != "" {
		c.JSON(http.StatusOK, gin.H{
			"enrollment_jwt": *enrollmentJWT,
			"ziti_id":        zitiID,
		})
		return
	}

	// Try to fetch from controller
	if s.zitiManager != nil {
		jwt, err := s.zitiManager.GetIdentityEnrollmentJWT(c.Request.Context(), zitiID)
		if err == nil && jwt != "" {
			// Update DB
			s.db.Pool.Exec(c.Request.Context(),
				"UPDATE ziti_identities SET enrollment_jwt=$1 WHERE id=$2", jwt, id)
			c.JSON(http.StatusOK, gin.H{
				"enrollment_jwt": jwt,
				"ziti_id":        zitiID,
			})
			return
		}
	}

	c.JSON(http.StatusGone, gin.H{
		"error":   "enrollment JWT not available (identity may already be enrolled)",
		"ziti_id": zitiID,
	})
}

// ---- Enable/Disable Ziti on Routes ----

func (s *Service) handleEnableZitiOnRoute(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	routeID := c.Param("id")

	var req struct {
		ServiceName string `json:"service_name" binding:"required"`
		Host        string `json:"host" binding:"required"`
		Port        int    `json:"port" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify route exists
	_, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	if err := s.zitiManager.SetupZitiForRoute(c.Request.Context(), routeID, req.ServiceName, req.Host, req.Port); err != nil {
		s.logger.Error("Failed to enable Ziti on route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logAuditEvent(c, "ziti_enabled_on_route", routeID, "proxy_route", map[string]interface{}{
		"service_name": req.ServiceName,
		"host":         req.Host,
		"port":         req.Port,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Ziti enabled on route", "service_name": req.ServiceName})
}

func (s *Service) handleDisableZitiOnRoute(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenZiti is not configured"})
		return
	}

	routeID := c.Param("id")

	// Verify route exists
	_, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	if err := s.zitiManager.TeardownZitiForRoute(c.Request.Context(), routeID); err != nil {
		s.logger.Error("Failed to disable Ziti on route", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logAuditEvent(c, "ziti_disabled_on_route", routeID, "proxy_route", nil)

	c.JSON(http.StatusOK, gin.H{"message": "Ziti disabled on route"})
}
