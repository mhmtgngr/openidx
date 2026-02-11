// Package access provides connection testing functionality
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ConnectionTestRequest represents a request to test a connection
type ConnectionTestRequest struct {
	TestType       string `json:"test_type"` // "upstream", "ziti", "guacamole", "full"
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// ConnectionTestResult represents the result of a connection test
type ConnectionTestResult struct {
	Success         bool                   `json:"success"`
	Tests           map[string]*TestResult `json:"tests"`
	OverallLatencyMs int64                 `json:"overall_latency_ms"`
	TestedAt        time.Time              `json:"tested_at"`
}

// TestResult represents the result of a single test
type TestResult struct {
	Success       bool                   `json:"success"`
	LatencyMs     int64                  `json:"latency_ms"`
	StatusCode    int                    `json:"status_code,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// handleTestConnection tests connectivity for a specific route
func (s *Service) handleTestConnection(c *gin.Context) {
	routeID := c.Param("id")

	var req ConnectionTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.TestType = "full"
		req.TimeoutSeconds = 10
	}
	if req.TestType == "" {
		req.TestType = "full"
	}
	if req.TimeoutSeconds == 0 || req.TimeoutSeconds > 60 {
		req.TimeoutSeconds = 10
	}

	// Get route info
	route, err := s.getRouteByID(c.Request.Context(), routeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()

	start := time.Now()
	result := &ConnectionTestResult{
		Success:  true,
		Tests:    make(map[string]*TestResult),
		TestedAt: start,
	}

	// Run tests based on test type
	switch req.TestType {
	case "upstream":
		result.Tests["upstream"] = s.testUpstreamConnectivity(ctx, route)
	case "ziti":
		if route.ZitiEnabled {
			result.Tests["ziti"] = s.testZitiConnectivity(ctx, route)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ziti not enabled on this route"})
			return
		}
	case "guacamole":
		if route.GuacamoleConnectionID != "" {
			result.Tests["guacamole"] = s.testGuacamoleConnectivity(ctx, route)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Guacamole not configured on this route"})
			return
		}
	case "full":
		// Test upstream
		result.Tests["upstream"] = s.testUpstreamConnectivity(ctx, route)

		// Test Ziti if enabled
		if route.ZitiEnabled {
			result.Tests["ziti"] = s.testZitiConnectivity(ctx, route)
		}

		// Test Guacamole if configured
		if route.GuacamoleConnectionID != "" {
			result.Tests["guacamole"] = s.testGuacamoleConnectivity(ctx, route)
		}

		// Test direct TCP connectivity for remote access routes
		if route.RouteType == "ssh" || route.RouteType == "rdp" || route.RouteType == "vnc" || route.RouteType == "telnet" {
			result.Tests["tcp"] = s.testTCPConnectivity(ctx, route.RemoteHost, route.RemotePort)
		}
	}

	// Calculate overall latency and success
	var totalLatency int64
	for _, test := range result.Tests {
		totalLatency += test.LatencyMs
		if !test.Success {
			result.Success = false
		}
	}
	result.OverallLatencyMs = time.Since(start).Milliseconds()

	// Get user ID for saving
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}

	// Save test result
	if err := s.saveConnectionTest(ctx, routeID, req.TestType, result, userID); err != nil {
		s.logger.Warn("Failed to save connection test", zap.Error(err))
	}

	c.JSON(http.StatusOK, result)
}

// handleGetConnectionTestHistory returns connection test history for a route
func (s *Service) handleGetConnectionTestHistory(c *gin.Context) {
	routeID := c.Param("id")
	limit := 20

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, route_id, test_type, success, latency_ms, error_message, details, tested_at, tested_by
		FROM connection_tests
		WHERE route_id = $1
		ORDER BY tested_at DESC
		LIMIT $2
	`, routeID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get test history"})
		return
	}
	defer rows.Close()

	type TestHistoryItem struct {
		ID           string                 `json:"id"`
		RouteID      string                 `json:"route_id"`
		TestType     string                 `json:"test_type"`
		Success      bool                   `json:"success"`
		LatencyMs    int                    `json:"latency_ms"`
		ErrorMessage string                 `json:"error_message,omitempty"`
		Details      map[string]interface{} `json:"details,omitempty"`
		TestedAt     time.Time              `json:"tested_at"`
		TestedBy     string                 `json:"tested_by,omitempty"`
	}

	var history []TestHistoryItem
	for rows.Next() {
		var item TestHistoryItem
		var errorMsg, testedBy *string
		var latency *int
		var detailsJSON []byte

		err := rows.Scan(&item.ID, &item.RouteID, &item.TestType, &item.Success,
			&latency, &errorMsg, &detailsJSON, &item.TestedAt, &testedBy)
		if err != nil {
			continue
		}

		if errorMsg != nil {
			item.ErrorMessage = *errorMsg
		}
		if testedBy != nil {
			item.TestedBy = *testedBy
		}
		if latency != nil {
			item.LatencyMs = *latency
		}
		if detailsJSON != nil {
			json.Unmarshal(detailsJSON, &item.Details)
		}

		history = append(history, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"tests": history,
		"total": len(history),
	})
}

func (s *Service) testUpstreamConnectivity(ctx context.Context, route *ProxyRoute) *TestResult {
	result := &TestResult{
		Details: make(map[string]interface{}),
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	start := time.Now()
	resp, err := client.Get(route.ToURL)
	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Details["url"] = route.ToURL
	result.Details["content_length"] = resp.ContentLength

	// Consider 2xx-4xx as successful connectivity (server responded)
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		result.Success = true
	} else {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return result
}

func (s *Service) testZitiConnectivity(ctx context.Context, route *ProxyRoute) *TestResult {
	result := &TestResult{
		Details: make(map[string]interface{}),
	}

	if s.zitiManager == nil || !s.zitiManager.IsInitialized() {
		result.Success = false
		result.ErrorMessage = "Ziti manager not available"
		return result
	}

	start := time.Now()

	// Check if service exists
	service, err := s.zitiManager.GetServiceByName(route.ZitiServiceName)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Service not found: %s", err.Error())
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	result.Details["service_id"] = service.ID
	result.Details["service_name"] = service.Name

	// Check if service is reachable through Ziti
	reachable, dialErr := s.zitiManager.TestServiceDial(ctx, route.ZitiServiceName)
	result.LatencyMs = time.Since(start).Milliseconds()

	if reachable {
		result.Success = true
		result.Details["service_reachable"] = true
	} else {
		result.Success = false
		result.Details["service_reachable"] = false
		if dialErr != nil {
			result.ErrorMessage = dialErr.Error()
		} else {
			result.ErrorMessage = "Service not reachable"
		}
	}

	return result
}

func (s *Service) testGuacamoleConnectivity(ctx context.Context, route *ProxyRoute) *TestResult {
	result := &TestResult{
		Details: make(map[string]interface{}),
	}

	if s.guacamoleClient == nil {
		result.Success = false
		result.ErrorMessage = "Guacamole client not available"
		return result
	}

	start := time.Now()

	// Check if connection exists and is valid
	conn, err := s.guacamoleClient.GetConnection(ctx, route.GuacamoleConnectionID)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Connection not found: %s", err.Error())
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	result.Details["connection_id"] = conn.ID
	result.Details["connection_name"] = conn.Name
	result.Details["protocol"] = conn.Protocol

	// Test if connection parameters are valid
	valid, validateErr := s.guacamoleClient.ValidateConnection(ctx, route.GuacamoleConnectionID)
	result.LatencyMs = time.Since(start).Milliseconds()

	if valid {
		result.Success = true
		result.Details["connection_valid"] = true
	} else {
		result.Success = false
		result.Details["connection_valid"] = false
		if validateErr != nil {
			result.ErrorMessage = validateErr.Error()
		}
	}

	return result
}

func (s *Service) testTCPConnectivity(ctx context.Context, host string, port int) *TestResult {
	result := &TestResult{
		Details: make(map[string]interface{}),
	}

	if host == "" || port == 0 {
		result.Success = false
		result.ErrorMessage = "Host or port not configured"
		return result
	}

	address := fmt.Sprintf("%s:%d", host, port)
	result.Details["address"] = address

	start := time.Now()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
		return result
	}
	conn.Close()

	result.Success = true
	result.Details["port_open"] = true

	return result
}

func (s *Service) saveConnectionTest(ctx context.Context, routeID, testType string, result *ConnectionTestResult, userID string) error {
	detailsJSON, _ := json.Marshal(result.Tests)

	var errorMsg *string
	for _, test := range result.Tests {
		if !test.Success && test.ErrorMessage != "" {
			errorMsg = &test.ErrorMessage
			break
		}
	}

	var testedBy *string
	if userID != "" {
		testedBy = &userID
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO connection_tests (id, route_id, test_type, success, latency_ms, error_message, details, tested_at, tested_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, uuid.New().String(), routeID, testType, result.Success, result.OverallLatencyMs, errorMsg, detailsJSON, result.TestedAt, testedBy)

	return err
}
