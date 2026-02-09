// Package access provides Ziti service auto-discovery functionality
package access

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DiscoveredService represents a Ziti service that can be imported
type DiscoveredService struct {
	ZitiID          string   `json:"ziti_id"`
	Name            string   `json:"name"`
	Protocol        string   `json:"protocol"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	ManagedByOpenIDX bool    `json:"managed_by_openidx"`
	CanImport       bool     `json:"can_import"`
	RoleAttributes  []string `json:"role_attributes,omitempty"`
}

// DiscoveryResult contains the results of a service discovery
type DiscoveryResult struct {
	DiscoveredServices   []DiscoveredService `json:"discovered_services"`
	AlreadyManaged       int                 `json:"already_managed"`
	AvailableForImport   int                 `json:"available_for_import"`
	DiscoveredAt         time.Time           `json:"discovered_at"`
}

// ImportServiceRequest represents a request to import a discovered service
type ImportServiceRequest struct {
	ZitiID      string `json:"ziti_id" binding:"required"`
	RouteName   string `json:"route_name"`
	FromURL     string `json:"from_url"`
	Description string `json:"description"`
}

// ImportResult represents the result of importing a service
type ImportResult struct {
	RouteID     string `json:"route_id"`
	RouteName   string `json:"route_name"`
	ServiceName string `json:"service_name"`
	Message     string `json:"message"`
}

// handleDiscoverZitiServices discovers unmanaged Ziti services
func (s *Service) handleDiscoverZitiServices(c *gin.Context) {
	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti manager not available"})
		return
	}

	result, err := s.discoverZitiServices(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to discover Ziti services", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleImportZitiService imports a discovered Ziti service as a proxy route
func (s *Service) handleImportZitiService(c *gin.Context) {
	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti manager not available"})
		return
	}

	var req ImportServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := s.importZitiService(c.Request.Context(), &req)
	if err != nil {
		s.logger.Error("Failed to import Ziti service", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Log audit event
	s.logAuditEvent(c, "ziti_service_imported", result.RouteID, "proxy_route", map[string]interface{}{
		"service_name": result.ServiceName,
		"ziti_id":      req.ZitiID,
	})

	c.JSON(http.StatusCreated, result)
}

// handleBulkImportZitiServices imports multiple discovered services
func (s *Service) handleBulkImportZitiServices(c *gin.Context) {
	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti manager not available"})
		return
	}

	var req struct {
		ZitiIDs []string `json:"ziti_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var results []ImportResult
	var errors []string

	for _, zitiID := range req.ZitiIDs {
		importReq := &ImportServiceRequest{
			ZitiID: zitiID,
		}
		result, err := s.importZitiService(c.Request.Context(), importReq)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %s", zitiID, err.Error()))
			continue
		}
		results = append(results, *result)
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": results,
		"errors":   errors,
		"total_requested": len(req.ZitiIDs),
		"total_imported":  len(results),
		"total_failed":    len(errors),
	})
}

func (s *Service) discoverZitiServices(ctx context.Context) (*DiscoveryResult, error) {
	// Get all services from Ziti controller
	zitiServices, err := s.zitiManager.ListServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list Ziti services: %w", err)
	}

	// Get managed services from our database
	rows, err := s.db.Pool.Query(ctx,
		`SELECT ziti_id FROM ziti_services WHERE ziti_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("failed to query managed services: %w", err)
	}
	defer rows.Close()

	managedSet := make(map[string]bool)
	for rows.Next() {
		var zitiID string
		if err := rows.Scan(&zitiID); err == nil {
			managedSet[zitiID] = true
		}
	}

	// Also check proxy_routes for ziti_service_name
	rows2, err := s.db.Pool.Query(ctx,
		`SELECT ziti_service_name FROM proxy_routes WHERE ziti_enabled = true AND ziti_service_name IS NOT NULL`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var serviceName string
			if err := rows2.Scan(&serviceName); err == nil {
				// Mark services by name as managed too
				for _, svc := range zitiServices {
					if svc.Name == serviceName {
						managedSet[svc.ID] = true
					}
				}
			}
		}
	}

	result := &DiscoveryResult{
		DiscoveredServices: make([]DiscoveredService, 0),
		DiscoveredAt:       time.Now(),
	}

	for _, svc := range zitiServices {
		isManaged := managedSet[svc.ID]

		discovered := DiscoveredService{
			ZitiID:           svc.ID,
			Name:             svc.Name,
			Protocol:         svc.Protocol,
			ManagedByOpenIDX: isManaged,
			CanImport:        !isManaged,
			RoleAttributes:   svc.RoleAttributes,
		}

		// Configs from Ziti API are config IDs (strings), not config objects.
		// Host/port info would require fetching each config by ID separately.
		// For discovery, we rely on the DB-stored host/port for managed services.

		result.DiscoveredServices = append(result.DiscoveredServices, discovered)

		if isManaged {
			result.AlreadyManaged++
		} else {
			result.AvailableForImport++
		}
	}

	return result, nil
}

func (s *Service) importZitiService(ctx context.Context, req *ImportServiceRequest) (*ImportResult, error) {
	// Get service details from Ziti
	service, err := s.zitiManager.GetService(req.ZitiID)
	if err != nil {
		return nil, fmt.Errorf("service not found in Ziti: %w", err)
	}

	// Check if already imported
	var existingRouteID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT r.id FROM proxy_routes r
		 JOIN ziti_services z ON z.route_id = r.id
		 WHERE z.ziti_id = $1`, req.ZitiID).Scan(&existingRouteID)
	if err == nil {
		return nil, fmt.Errorf("service already imported as route %s", existingRouteID)
	}

	// Determine route name
	routeName := req.RouteName
	if routeName == "" {
		routeName = service.Name
	}

	// Determine from_url
	fromURL := req.FromURL
	if fromURL == "" {
		// Generate a URL path based on service name
		safeName := strings.ReplaceAll(strings.ToLower(service.Name), " ", "-")
		fromURL = "/" + safeName
	}

	// Create the proxy route
	routeID := uuid.New().String()
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("Imported from Ziti service: %s", service.Name)
	}

	// Determine toURL (will be routed through Ziti)
	toURL := fmt.Sprintf("ziti://%s", service.Name)

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO proxy_routes (id, name, description, from_url, to_url,
		                          ziti_enabled, ziti_service_name, enabled, require_auth)
		VALUES ($1, $2, $3, $4, $5, true, $6, true, true)
	`, routeID, routeName, description, fromURL, toURL, service.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy route: %w", err)
	}

	// Link in ziti_services table
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO ziti_services (id, ziti_id, name, route_id, enabled)
		VALUES ($1, $2, $3, $4, true)
	`, uuid.New().String(), req.ZitiID, service.Name, routeID)
	if err != nil {
		// Rollback the route
		s.db.Pool.Exec(ctx, `DELETE FROM proxy_routes WHERE id = $1`, routeID)
		return nil, fmt.Errorf("failed to link Ziti service: %w", err)
	}

	// Create feature record
	if s.featureManager != nil {
		s.featureManager.getOrCreateFeature(ctx, routeID, FeatureZiti)
		s.db.Pool.Exec(ctx, `
			UPDATE service_features
			SET enabled = true, status = 'enabled',
			    resource_ids = $1,
			    enabled_at = NOW()
			WHERE route_id = $2 AND feature_name = 'ziti'
		`, fmt.Sprintf(`{"ziti_service_id": "%s", "ziti_service_name": "%s"}`, req.ZitiID, service.Name), routeID)
	}

	s.logger.Info("Imported Ziti service as proxy route",
		zap.String("ziti_id", req.ZitiID),
		zap.String("service_name", service.Name),
		zap.String("route_id", routeID))

	return &ImportResult{
		RouteID:     routeID,
		RouteName:   routeName,
		ServiceName: service.Name,
		Message:     "Service imported successfully",
	}, nil
}

// handleGetUnmanagedServicesCount returns a quick count of importable services
func (s *Service) handleGetUnmanagedServicesCount(c *gin.Context) {
	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		c.JSON(http.StatusOK, gin.H{"count": 0, "available": false})
		return
	}

	result, err := s.discoverZitiServices(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"count": 0, "available": true, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"count":     result.AvailableForImport,
		"available": true,
		"managed":   result.AlreadyManaged,
		"total":     len(result.DiscoveredServices),
	})
}
