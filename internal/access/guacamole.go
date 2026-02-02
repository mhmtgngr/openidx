// Package access - Apache Guacamole integration for clientless remote access (SSH/RDP/VNC/Telnet)
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// GuacamoleClient communicates with the Apache Guacamole REST API to manage connections
type GuacamoleClient struct {
	baseURL    string
	username   string
	password   string
	authToken  string
	dataSource string
	httpClient *http.Client
	db         *database.PostgresDB
	logger     *zap.Logger
}

// GuacConnection represents a Guacamole connection
type GuacConnection struct {
	ID                    string            `json:"id"`
	RouteID               string            `json:"route_id"`
	GuacamoleConnectionID string            `json:"guacamole_connection_id"`
	Protocol              string            `json:"protocol"`
	Hostname              string            `json:"hostname"`
	Port                  int               `json:"port"`
	Parameters            map[string]string `json:"parameters"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// NewGuacamoleClient creates and authenticates a Guacamole API client
func NewGuacamoleClient(cfg *config.Config, db *database.PostgresDB, logger *zap.Logger) (*GuacamoleClient, error) {
	if cfg.GuacamoleURL == "" {
		return nil, fmt.Errorf("GUACAMOLE_URL is not configured")
	}

	gc := &GuacamoleClient{
		baseURL:    strings.TrimRight(cfg.GuacamoleURL, "/"),
		username:   cfg.GuacamoleAdminUser,
		password:   cfg.GuacamoleAdminPassword,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		db:         db,
		logger:     logger.With(zap.String("component", "guacamole")),
	}

	// Authenticate to get a token
	if err := gc.authenticate(cfg.GuacamoleAdminUser, cfg.GuacamoleAdminPassword); err != nil {
		return nil, fmt.Errorf("failed to authenticate to Guacamole: %w", err)
	}

	gc.logger.Info("Authenticated to Apache Guacamole", zap.String("url", gc.baseURL))
	return gc, nil
}

func (gc *GuacamoleClient) authenticate(username, password string) error {
	data := url.Values{
		"username": {username},
		"password": {password},
	}

	resp, err := gc.httpClient.PostForm(gc.baseURL+"/api/tokens", data)
	if err != nil {
		return fmt.Errorf("guacamole auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("guacamole auth failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AuthToken  string `json:"authToken"`
		DataSource string `json:"dataSource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode guacamole auth response: %w", err)
	}

	gc.authToken = result.AuthToken
	gc.dataSource = result.DataSource
	return nil
}

// apiRequest makes an authenticated request to the Guacamole API
func (gc *GuacamoleClient) apiRequest(method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reqBody = strings.NewReader(string(data))
	}

	apiURL := fmt.Sprintf("%s/api/session/data/%s%s?token=%s",
		gc.baseURL, gc.dataSource, path, gc.authToken)

	req, err := http.NewRequest(method, apiURL, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("guacamole API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// Re-authenticate on 403 and retry once
	if resp.StatusCode == http.StatusForbidden {
		if err := gc.authenticate(gc.username, gc.password); err != nil {
			return respBody, resp.StatusCode, fmt.Errorf("re-authentication failed: %w", err)
		}

		apiURL = fmt.Sprintf("%s/api/session/data/%s%s?token=%s",
			gc.baseURL, gc.dataSource, path, gc.authToken)
		if body != nil {
			data, _ := json.Marshal(body)
			reqBody = strings.NewReader(string(data))
		}
		req, _ = http.NewRequest(method, apiURL, reqBody)
		req.Header.Set("Content-Type", "application/json")

		resp, err = gc.httpClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)
	}

	return respBody, resp.StatusCode, nil
}

// CreateConnection creates a new connection in Guacamole
func (gc *GuacamoleClient) CreateConnection(name, protocol, hostname string, port int, params map[string]string) (string, error) {
	if params == nil {
		params = make(map[string]string)
	}
	params["hostname"] = hostname
	params["port"] = fmt.Sprintf("%d", port)

	// Set protocol-specific defaults
	switch protocol {
	case "ssh":
		if _, ok := params["color-scheme"]; !ok {
			params["color-scheme"] = "green-black"
		}
		if _, ok := params["font-size"]; !ok {
			params["font-size"] = "14"
		}
	case "rdp":
		if _, ok := params["security"]; !ok {
			params["security"] = "nla"
		}
		if _, ok := params["ignore-cert"]; !ok {
			params["ignore-cert"] = "true"
		}
	case "vnc":
		// VNC defaults are fine
	}

	body := map[string]interface{}{
		"name":       name,
		"protocol":   protocol,
		"parameters": params,
		"attributes": map[string]string{
			"max-connections":          "10",
			"max-connections-per-user": "3",
		},
	}

	respData, statusCode, err := gc.apiRequest("POST", "/connections", body)
	if err != nil {
		return "", fmt.Errorf("failed to create guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d creating guacamole connection: %s", statusCode, string(respData))
	}

	var resp struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse guacamole connection response: %w", err)
	}

	gc.logger.Info("Created Guacamole connection",
		zap.String("name", name),
		zap.String("protocol", protocol),
		zap.String("identifier", resp.Identifier))

	return resp.Identifier, nil
}

// DeleteConnection removes a connection from Guacamole
func (gc *GuacamoleClient) DeleteConnection(connID string) error {
	_, statusCode, err := gc.apiRequest("DELETE", "/connections/"+connID, nil)
	if err != nil {
		return fmt.Errorf("failed to delete guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent && statusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status %d deleting guacamole connection", statusCode)
	}

	gc.logger.Info("Deleted Guacamole connection", zap.String("identifier", connID))
	return nil
}

// UpdateConnection updates an existing Guacamole connection
func (gc *GuacamoleClient) UpdateConnection(connID, name, protocol, hostname string, port int, params map[string]string) error {
	if params == nil {
		params = make(map[string]string)
	}
	params["hostname"] = hostname
	params["port"] = fmt.Sprintf("%d", port)

	body := map[string]interface{}{
		"identifier": connID,
		"name":       name,
		"protocol":   protocol,
		"parameters": params,
	}

	_, statusCode, err := gc.apiRequest("PUT", "/connections/"+connID, body)
	if err != nil {
		return fmt.Errorf("failed to update guacamole connection: %w", err)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d updating guacamole connection", statusCode)
	}

	return nil
}

// GetConnectionURL returns the URL to open a Guacamole connection in the browser
func (gc *GuacamoleClient) GetConnectionURL(connID string) string {
	// The Guacamole client URL format: /#/client/{base64(connID + \0 + c + \0 + dataSource)}
	// Simplified: just return the base URL with connection reference
	return fmt.Sprintf("%s/#/client/%s?token=%s", gc.baseURL, connID, gc.authToken)
}

// ---- Database operations for tracking Guacamole connections ----

// SaveGuacConnection persists a Guacamole connection mapping to the database
func (gc *GuacamoleClient) SaveGuacConnection(ctx context.Context, routeID, connID, protocol, hostname string, port int, params map[string]string) error {
	paramsJSON, _ := json.Marshal(params)

	_, err := gc.db.Pool.Exec(ctx,
		`INSERT INTO guacamole_connections (route_id, guacamole_connection_id, protocol, hostname, port, parameters, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		 ON CONFLICT (route_id) DO UPDATE SET
		   guacamole_connection_id=$2, protocol=$3, hostname=$4, port=$5, parameters=$6, updated_at=NOW()`,
		routeID, connID, protocol, hostname, port, paramsJSON)
	if err != nil {
		return fmt.Errorf("failed to save guacamole connection mapping: %w", err)
	}
	return nil
}

// DeleteGuacConnectionByRoute removes the Guacamole connection mapping for a route
func (gc *GuacamoleClient) DeleteGuacConnectionByRoute(ctx context.Context, routeID string) error {
	var connID string
	err := gc.db.Pool.QueryRow(ctx,
		"SELECT guacamole_connection_id FROM guacamole_connections WHERE route_id=$1", routeID).
		Scan(&connID)
	if err != nil {
		return nil // no connection to delete
	}

	// Delete from Guacamole
	gc.DeleteConnection(connID)

	// Delete from database
	gc.db.Pool.Exec(ctx, "DELETE FROM guacamole_connections WHERE route_id=$1", routeID)
	return nil
}

// ListGuacConnections returns all tracked Guacamole connections
func (gc *GuacamoleClient) ListGuacConnections(ctx context.Context) ([]GuacConnection, error) {
	rows, err := gc.db.Pool.Query(ctx,
		`SELECT id, route_id, guacamole_connection_id, protocol, hostname, port, parameters, created_at, updated_at
		 FROM guacamole_connections ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query guacamole connections: %w", err)
	}
	defer rows.Close()

	var conns []GuacConnection
	for rows.Next() {
		var c GuacConnection
		var paramsJSON []byte
		err := rows.Scan(&c.ID, &c.RouteID, &c.GuacamoleConnectionID, &c.Protocol,
			&c.Hostname, &c.Port, &paramsJSON, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			gc.logger.Warn("Failed to scan guacamole connection row", zap.Error(err))
			continue
		}
		if paramsJSON != nil {
			json.Unmarshal(paramsJSON, &c.Parameters)
		}
		if c.Parameters == nil {
			c.Parameters = make(map[string]string)
		}
		conns = append(conns, c)
	}

	if conns == nil {
		conns = []GuacConnection{}
	}
	return conns, nil
}

// ---- HTTP Handlers ----

// handleListGuacamoleConnections lists all Guacamole connections
func (s *Service) handleListGuacamoleConnections(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	conns, err := s.guacamoleClient.ListGuacConnections(c.Request.Context())
	if err != nil {
		s.logger.Error("Failed to list guacamole connections", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"connections": conns})
}

// handleGuacamoleConnect returns the URL to connect to a Guacamole session for a route
func (s *Service) handleGuacamoleConnect(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	routeID := c.Param("routeId")

	// Look up the Guacamole connection for this route
	var connID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT guacamole_connection_id FROM guacamole_connections WHERE route_id=$1", routeID).
		Scan(&connID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no Guacamole connection found for this route"})
		return
	}

	connectURL := s.guacamoleClient.GetConnectionURL(connID)

	c.JSON(http.StatusOK, gin.H{
		"connect_url":   connectURL,
		"connection_id": connID,
		"route_id":      routeID,
	})
}

// provisionGuacamoleForRoute creates a Guacamole connection when a remote-access route is created/updated
func (s *Service) provisionGuacamoleForRoute(ctx context.Context, route *ProxyRoute) error {
	if s.guacamoleClient == nil {
		return nil
	}

	// Only provision for remote access route types
	if route.RouteType != "ssh" && route.RouteType != "rdp" && route.RouteType != "vnc" && route.RouteType != "telnet" {
		return nil
	}

	if route.RemoteHost == "" || route.RemotePort == 0 {
		return fmt.Errorf("remote_host and remote_port are required for %s routes", route.RouteType)
	}

	connName := fmt.Sprintf("openidx-%s-%s", route.RouteType, route.Name)
	params := map[string]string{}

	connID, err := s.guacamoleClient.CreateConnection(connName, route.RouteType, route.RemoteHost, route.RemotePort, params)
	if err != nil {
		return fmt.Errorf("failed to create guacamole connection: %w", err)
	}

	// Save mapping
	if err := s.guacamoleClient.SaveGuacConnection(ctx, route.ID, connID, route.RouteType, route.RemoteHost, route.RemotePort, params); err != nil {
		return fmt.Errorf("failed to save guacamole connection mapping: %w", err)
	}

	// Update route with connection ID
	s.db.Pool.Exec(ctx,
		"UPDATE proxy_routes SET guacamole_connection_id=$1, updated_at=NOW() WHERE id=$2",
		connID, route.ID)

	s.logger.Info("Provisioned Guacamole connection for route",
		zap.String("route_id", route.ID),
		zap.String("connection_id", connID),
		zap.String("protocol", route.RouteType))

	return nil
}

// deprovisionGuacamoleForRoute removes the Guacamole connection when a route is deleted
func (s *Service) deprovisionGuacamoleForRoute(ctx context.Context, routeID string) {
	if s.guacamoleClient == nil {
		return
	}

	if err := s.guacamoleClient.DeleteGuacConnectionByRoute(ctx, routeID); err != nil {
		s.logger.Warn("Failed to deprovision guacamole connection",
			zap.String("route_id", routeID), zap.Error(err))
	}
}
