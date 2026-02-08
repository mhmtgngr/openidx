// Package access provides health check handlers for integrations
package access

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// IntegrationHealth represents the health of a single integration
type IntegrationHealth struct {
	Status            string    `json:"status"`
	Available         bool      `json:"available"`
	LastCheck         time.Time `json:"last_check"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	Details           map[string]interface{} `json:"details,omitempty"`
}

// ZitiHealth represents detailed Ziti health
type ZitiHealth struct {
	Status            string `json:"status"`
	ControllerReachable bool `json:"controller_reachable"`
	RoutersOnline     int    `json:"routers_online"`
	RoutersTotal      int    `json:"routers_total"`
	ServicesCount     int    `json:"services_count"`
	IdentitiesCount   int    `json:"identities_count"`
	LastCheck         time.Time `json:"last_check"`
	ErrorMessage      string `json:"error_message,omitempty"`
	Version           string `json:"version,omitempty"`
}

// GuacamoleHealth represents detailed Guacamole health
type GuacamoleHealth struct {
	Status           string `json:"status"`
	ServerReachable  bool   `json:"server_reachable"`
	Authenticated    bool   `json:"authenticated"`
	ConnectionsCount int    `json:"connections_count"`
	ActiveSessions   int    `json:"active_sessions"`
	LastCheck        time.Time `json:"last_check"`
	ErrorMessage     string `json:"error_message,omitempty"`
	Version          string `json:"version,omitempty"`
}

// BrowZerHealth represents detailed BrowZer health
type BrowZerHealth struct {
	Status          string `json:"status"`
	Bootstrapped    bool   `json:"bootstrapped"`
	JWTSignerValid  bool   `json:"jwt_signer_valid"`
	AuthPolicyValid bool   `json:"auth_policy_valid"`
	LastCheck       time.Time `json:"last_check"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// IntegrationsHealthResponse represents the overall health response
type IntegrationsHealthResponse struct {
	Status       string                      `json:"status"`
	Timestamp    time.Time                   `json:"timestamp"`
	Integrations map[string]*IntegrationHealth `json:"integrations"`
}

// handleHealthIntegrations returns health status for all integrations
func (s *Service) handleHealthIntegrations(c *gin.Context) {
	ctx := c.Request.Context()

	response := &IntegrationsHealthResponse{
		Status:       "healthy",
		Timestamp:    time.Now(),
		Integrations: make(map[string]*IntegrationHealth),
	}

	// Check Ziti
	zitiHealth := s.checkZitiHealth(ctx)
	response.Integrations["ziti"] = &IntegrationHealth{
		Status:       zitiHealth.Status,
		Available:    zitiHealth.ControllerReachable,
		LastCheck:    zitiHealth.LastCheck,
		ErrorMessage: zitiHealth.ErrorMessage,
		Details: map[string]interface{}{
			"routers_online":    zitiHealth.RoutersOnline,
			"routers_total":     zitiHealth.RoutersTotal,
			"services_count":    zitiHealth.ServicesCount,
			"identities_count":  zitiHealth.IdentitiesCount,
		},
	}
	if zitiHealth.Status != "healthy" && zitiHealth.Status != "unavailable" {
		response.Status = "degraded"
	}

	// Check Guacamole
	guacHealth := s.checkGuacamoleHealth(ctx)
	response.Integrations["guacamole"] = &IntegrationHealth{
		Status:       guacHealth.Status,
		Available:    guacHealth.ServerReachable,
		LastCheck:    guacHealth.LastCheck,
		ErrorMessage: guacHealth.ErrorMessage,
		Details: map[string]interface{}{
			"authenticated":     guacHealth.Authenticated,
			"connections_count": guacHealth.ConnectionsCount,
			"active_sessions":   guacHealth.ActiveSessions,
		},
	}
	if guacHealth.Status != "healthy" && guacHealth.Status != "unavailable" {
		response.Status = "degraded"
	}

	// Check BrowZer
	browzerHealth := s.checkBrowZerHealth(ctx)
	response.Integrations["browzer"] = &IntegrationHealth{
		Status:       browzerHealth.Status,
		Available:    browzerHealth.Bootstrapped,
		LastCheck:    browzerHealth.LastCheck,
		ErrorMessage: browzerHealth.ErrorMessage,
		Details: map[string]interface{}{
			"jwt_signer_valid":  browzerHealth.JWTSignerValid,
			"auth_policy_valid": browzerHealth.AuthPolicyValid,
		},
	}
	if browzerHealth.Status != "healthy" && browzerHealth.Status != "unavailable" {
		response.Status = "degraded"
	}

	c.JSON(http.StatusOK, response)
}

// handleHealthZiti returns detailed Ziti health status
func (s *Service) handleHealthZiti(c *gin.Context) {
	health := s.checkZitiHealth(c.Request.Context())

	statusCode := http.StatusOK
	if health.Status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	} else if health.Status == "degraded" {
		statusCode = http.StatusOK
	}

	c.JSON(statusCode, health)
}

// handleHealthGuacamole returns detailed Guacamole health status
func (s *Service) handleHealthGuacamole(c *gin.Context) {
	health := s.checkGuacamoleHealth(c.Request.Context())

	statusCode := http.StatusOK
	if health.Status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// handleHealthBrowZer returns detailed BrowZer health status
func (s *Service) handleHealthBrowZer(c *gin.Context) {
	health := s.checkBrowZerHealth(c.Request.Context())

	statusCode := http.StatusOK
	if health.Status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// handleHealthService returns health status for a specific service
func (s *Service) handleHealthService(c *gin.Context) {
	routeID := c.Param("id")

	// Get route info
	route, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found"})
		return
	}

	health := &ServiceHealthResponse{
		RouteID:     routeID,
		RouteName:   route.Name,
		Status:      "healthy",
		Timestamp:   time.Now(),
		Features:    make(map[string]*FeatureHealth),
	}

	// Check upstream connectivity
	upstreamHealth := s.checkUpstreamHealth(c.Request.Context(), route.ToURL)
	health.Upstream = upstreamHealth
	if upstreamHealth.Status != "healthy" {
		health.Status = "degraded"
	}

	// Check Ziti if enabled
	if route.ZitiEnabled {
		zitiHealth := s.checkZitiServiceHealth(c.Request.Context(), route.ZitiServiceName)
		health.Features["ziti"] = zitiHealth
		if zitiHealth.Status != "healthy" {
			health.Status = "degraded"
		}
	}

	// Check Guacamole if configured
	if route.GuacamoleConnectionID != "" {
		guacHealth := s.checkGuacamoleConnectionHealth(c.Request.Context(), route.GuacamoleConnectionID)
		health.Features["guacamole"] = guacHealth
		if guacHealth.Status != "healthy" {
			health.Status = "degraded"
		}
	}

	c.JSON(http.StatusOK, health)
}

// ServiceHealthResponse represents the health of a specific service
type ServiceHealthResponse struct {
	RouteID   string                    `json:"route_id"`
	RouteName string                    `json:"route_name"`
	Status    string                    `json:"status"`
	Timestamp time.Time                 `json:"timestamp"`
	Upstream  *UpstreamHealth           `json:"upstream"`
	Features  map[string]*FeatureHealth `json:"features"`
}

// UpstreamHealth represents upstream connectivity health
type UpstreamHealth struct {
	Status       string `json:"status"`
	Reachable    bool   `json:"reachable"`
	LatencyMs    int    `json:"latency_ms"`
	StatusCode   int    `json:"status_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// FeatureHealth represents health of a specific feature
type FeatureHealth struct {
	Status       string `json:"status"`
	Operational  bool   `json:"operational"`
	ErrorMessage string `json:"error_message,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

func (s *Service) checkZitiHealth(ctx context.Context) *ZitiHealth {
	health := &ZitiHealth{
		Status:    "unavailable",
		LastCheck: time.Now(),
	}

	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		health.ErrorMessage = "Ziti manager not configured"
		return health
	}

	// Check controller connectivity
	controllerReachable, err := s.zitiManager.CheckControllerHealth(ctx)
	health.ControllerReachable = controllerReachable
	if !controllerReachable {
		health.Status = "unhealthy"
		if err != nil {
			health.ErrorMessage = err.Error()
		}
		return health
	}

	// Get counts
	services, _ := s.zitiManager.ListServices(ctx)
	health.ServicesCount = len(services)

	identities, _ := s.zitiManager.ListIdentities(ctx)
	health.IdentitiesCount = len(identities)

	routers, _ := s.zitiManager.ListEdgeRouters(ctx)
	health.RoutersTotal = len(routers)
	for _, r := range routers {
		if r.IsOnline {
			health.RoutersOnline++
		}
	}

	// Determine status
	if health.RoutersOnline == 0 && health.RoutersTotal > 0 {
		health.Status = "degraded"
		health.ErrorMessage = "No edge routers online"
	} else if health.RoutersOnline < health.RoutersTotal {
		health.Status = "degraded"
	} else {
		health.Status = "healthy"
	}

	return health
}

func (s *Service) checkGuacamoleHealth(ctx context.Context) *GuacamoleHealth {
	health := &GuacamoleHealth{
		Status:    "unavailable",
		LastCheck: time.Now(),
	}

	if s.guacamoleClient == nil {
		health.ErrorMessage = "Guacamole client not configured"
		return health
	}

	// Check server connectivity
	reachable, err := s.guacamoleClient.CheckHealth(ctx)
	health.ServerReachable = reachable
	if !reachable {
		health.Status = "unhealthy"
		if err != nil {
			health.ErrorMessage = err.Error()
		}
		return health
	}

	// Check authentication
	health.Authenticated = s.guacamoleClient.IsAuthenticated()

	// Get connection count
	connections, err := s.guacamoleClient.ListConnections(ctx)
	if err == nil {
		health.ConnectionsCount = len(connections)
	}

	// Get active sessions
	health.ActiveSessions = s.guacamoleClient.GetActiveSessionCount()

	if health.Authenticated {
		health.Status = "healthy"
	} else {
		health.Status = "degraded"
		health.ErrorMessage = "Not authenticated to Guacamole server"
	}

	return health
}

func (s *Service) checkBrowZerHealth(ctx context.Context) *BrowZerHealth {
	health := &BrowZerHealth{
		Status:    "unavailable",
		LastCheck: time.Now(),
	}

	// Check if BrowZer is configured
	var enabled bool
	var externalJwtSignerID, authPolicyID *string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT enabled, external_jwt_signer_id, auth_policy_id
		 FROM ziti_browzer_config LIMIT 1`).Scan(&enabled, &externalJwtSignerID, &authPolicyID)
	if err != nil {
		health.ErrorMessage = "BrowZer not configured"
		return health
	}

	if !enabled {
		health.Status = "disabled"
		return health
	}

	health.Bootstrapped = true

	// Check JWT signer
	if externalJwtSignerID != nil && *externalJwtSignerID != "" {
		health.JWTSignerValid = true
	}

	// Check auth policy
	if authPolicyID != nil && *authPolicyID != "" {
		health.AuthPolicyValid = true
	}

	if health.JWTSignerValid && health.AuthPolicyValid {
		health.Status = "healthy"
	} else {
		health.Status = "degraded"
		if !health.JWTSignerValid {
			health.ErrorMessage = "JWT signer not configured"
		} else if !health.AuthPolicyValid {
			health.ErrorMessage = "Auth policy not configured"
		}
	}

	return health
}

func (s *Service) checkUpstreamHealth(ctx context.Context, toURL string) *UpstreamHealth {
	health := &UpstreamHealth{
		Status: "unknown",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(toURL)
	latency := time.Since(start)

	health.LatencyMs = int(latency.Milliseconds())

	if err != nil {
		health.Status = "unhealthy"
		health.Reachable = false
		health.ErrorMessage = err.Error()
		return health
	}
	defer resp.Body.Close()

	health.Reachable = true
	health.StatusCode = resp.StatusCode

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		health.Status = "healthy"
	} else {
		health.Status = "degraded"
	}

	return health
}

func (s *Service) checkZitiServiceHealth(ctx context.Context, serviceName string) *FeatureHealth {
	health := &FeatureHealth{
		Status:  "unknown",
		Details: make(map[string]interface{}),
	}

	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		health.Status = "unavailable"
		health.ErrorMessage = "Ziti manager not available"
		return health
	}

	// Check if service exists and is reachable
	service, err := s.zitiManager.GetServiceByName(serviceName)
	if err != nil {
		health.Status = "unhealthy"
		health.ErrorMessage = "Service not found in Ziti"
		return health
	}

	health.Operational = true
	health.Status = "healthy"
	health.Details["ziti_service_id"] = service.ID
	health.Details["service_name"] = service.Name

	return health
}

func (s *Service) checkGuacamoleConnectionHealth(ctx context.Context, connectionID string) *FeatureHealth {
	health := &FeatureHealth{
		Status:  "unknown",
		Details: make(map[string]interface{}),
	}

	if s.guacamoleClient == nil {
		health.Status = "unavailable"
		health.ErrorMessage = "Guacamole client not available"
		return health
	}

	// Check if connection exists
	conn, err := s.guacamoleClient.GetConnection(ctx, connectionID)
	if err != nil {
		health.Status = "unhealthy"
		health.ErrorMessage = "Connection not found in Guacamole"
		return health
	}

	health.Operational = true
	health.Status = "healthy"
	health.Details["connection_id"] = conn.ID
	health.Details["protocol"] = conn.Protocol

	return health
}
