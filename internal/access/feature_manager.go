// Package access provides feature management for unified service-based control
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// FeatureName represents a toggleable feature
type FeatureName string

const (
	FeatureZiti      FeatureName = "ziti"
	FeatureBrowZer   FeatureName = "browzer"
	FeatureGuacamole FeatureName = "guacamole"
)

// FeatureStatus represents the current status of a feature
type FeatureStatus string

const (
	FeatureStatusDisabled FeatureStatus = "disabled"
	FeatureStatusEnabled  FeatureStatus = "enabled"
	FeatureStatusPending  FeatureStatus = "pending"
	FeatureStatusError    FeatureStatus = "error"
)

// HealthStatus represents the health of a feature
type HealthStatus string

const (
	HealthStatusUnknown  HealthStatus = "unknown"
	HealthStatusHealthy  HealthStatus = "healthy"
	HealthStatusDegraded HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// ServiceFeature represents a feature attached to a service/route
type ServiceFeature struct {
	ID              string            `json:"id"`
	RouteID         string            `json:"route_id"`
	FeatureName     FeatureName       `json:"feature_name"`
	Enabled         bool              `json:"enabled"`
	Config          map[string]interface{} `json:"config"`
	ResourceIDs     map[string]string `json:"resource_ids"`
	Status          FeatureStatus     `json:"status"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	LastHealthCheck *time.Time        `json:"last_health_check,omitempty"`
	HealthStatus    HealthStatus      `json:"health_status"`
	EnabledAt       *time.Time        `json:"enabled_at,omitempty"`
	EnabledBy       string            `json:"enabled_by,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// ServiceStatus represents the complete status of a service with all features
type ServiceStatus struct {
	RouteID     string                        `json:"route_id"`
	RouteName   string                        `json:"route_name"`
	RouteType   string                        `json:"route_type"`
	Features    map[FeatureName]*ServiceFeature `json:"features"`
	OverallHealth HealthStatus                `json:"overall_health"`
	LastUpdated time.Time                     `json:"last_updated"`
}

// FeatureConfig contains configuration for enabling a feature
type FeatureConfig struct {
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

// FeatureManager handles feature toggle operations
type FeatureManager struct {
	db                   *database.PostgresDB
	logger               *zap.Logger
	zitiManager          *ZitiManager
	guacamoleClient      *GuacamoleClient
	browzerTargetManager *BrowZerTargetManager
}

// NewFeatureManager creates a new FeatureManager
func NewFeatureManager(db *database.PostgresDB, logger *zap.Logger) *FeatureManager {
	return &FeatureManager{
		db:     db,
		logger: logger.With(zap.String("component", "feature_manager")),
	}
}

// SetZitiManager sets the Ziti manager
func (fm *FeatureManager) SetZitiManager(zm *ZitiManager) {
	fm.zitiManager = zm
}

// SetGuacamoleClient sets the Guacamole client
func (fm *FeatureManager) SetGuacamoleClient(gc *GuacamoleClient) {
	fm.guacamoleClient = gc
}

// SetBrowZerTargetManager sets the BrowZer target manager for config file generation
func (fm *FeatureManager) SetBrowZerTargetManager(btm *BrowZerTargetManager) {
	fm.browzerTargetManager = btm
}

// EnableFeature enables a feature on a route
func (fm *FeatureManager) EnableFeature(ctx context.Context, routeID string, feature FeatureName, config *FeatureConfig, userID string) error {
	// Validate dependencies
	if err := fm.validateFeatureDependencies(ctx, routeID, feature); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// Validate route type compatibility
	if err := fm.validateRouteTypeCompatibility(ctx, routeID, feature); err != nil {
		return fmt.Errorf("route type incompatible: %w", err)
	}

	// Get or create feature record
	featureRecord, err := fm.getOrCreateFeature(ctx, routeID, feature)
	if err != nil {
		return fmt.Errorf("failed to get/create feature: %w", err)
	}

	// If already enabled, return
	if featureRecord.Enabled {
		return nil
	}

	// Set status to pending while provisioning
	if err := fm.updateFeatureStatus(ctx, featureRecord.ID, FeatureStatusPending, ""); err != nil {
		return err
	}

	// Provision the feature
	resourceIDs, err := fm.provisionFeature(ctx, routeID, feature, config)
	if err != nil {
		fm.updateFeatureStatus(ctx, featureRecord.ID, FeatureStatusError, err.Error())
		return fmt.Errorf("failed to provision feature: %w", err)
	}

	// Update feature record
	configJSON, _ := json.Marshal(config)
	resourceJSON, _ := json.Marshal(resourceIDs)
	now := time.Now()

	// Convert empty userID to nil for UUID column compatibility
	var enabledBy interface{}
	if userID != "" {
		enabledBy = userID
	}

	_, err = fm.db.Pool.Exec(ctx, `
		UPDATE service_features
		SET enabled = true,
		    config = $1,
		    resource_ids = $2,
		    status = $3,
		    error_message = NULL,
		    enabled_at = $4,
		    enabled_by = $5,
		    updated_at = NOW()
		WHERE id = $6
	`, configJSON, resourceJSON, FeatureStatusEnabled, now, enabledBy, featureRecord.ID)

	if err != nil {
		return fmt.Errorf("failed to update feature record: %w", err)
	}

	// Update the proxy_route table for backward compatibility
	if err := fm.syncRouteFlags(ctx, routeID, feature, true, resourceIDs); err != nil {
		fm.logger.Warn("Failed to sync route flags", zap.Error(err))
	}

	fm.logger.Info("Feature enabled",
		zap.String("route_id", routeID),
		zap.String("feature", string(feature)),
		zap.String("user_id", userID))

	return nil
}

// DisableFeature disables a feature on a route
func (fm *FeatureManager) DisableFeature(ctx context.Context, routeID string, feature FeatureName) error {
	// Check for dependent features that need to be disabled first
	dependents, err := fm.getDependentFeatures(ctx, routeID, feature)
	if err != nil {
		return fmt.Errorf("failed to check dependents: %w", err)
	}

	// Disable dependents first (cascade)
	for _, dep := range dependents {
		fm.logger.Info("Cascading disable to dependent feature",
			zap.String("feature", string(dep)),
			zap.String("route_id", routeID))
		if err := fm.DisableFeature(ctx, routeID, dep); err != nil {
			return fmt.Errorf("failed to disable dependent feature %s: %w", dep, err)
		}
	}

	// Get feature record
	featureRecord, err := fm.getFeature(ctx, routeID, feature)
	if err != nil {
		return fmt.Errorf("feature not found: %w", err)
	}

	if !featureRecord.Enabled {
		return nil // Already disabled
	}

	// Deprovision resources
	if err := fm.deprovisionFeature(ctx, routeID, feature, featureRecord.ResourceIDs); err != nil {
		fm.logger.Warn("Failed to deprovision feature (continuing)", zap.Error(err))
	}

	// Update feature record
	_, err = fm.db.Pool.Exec(ctx, `
		UPDATE service_features
		SET enabled = false,
		    status = $1,
		    error_message = NULL,
		    resource_ids = '{}',
		    updated_at = NOW()
		WHERE id = $2
	`, FeatureStatusDisabled, featureRecord.ID)

	if err != nil {
		return fmt.Errorf("failed to update feature record: %w", err)
	}

	// Update the proxy_route table for backward compatibility
	if err := fm.syncRouteFlags(ctx, routeID, feature, false, nil); err != nil {
		fm.logger.Warn("Failed to sync route flags", zap.Error(err))
	}

	fm.logger.Info("Feature disabled",
		zap.String("route_id", routeID),
		zap.String("feature", string(feature)))

	return nil
}

// GetServiceStatus returns the complete status of a service
func (fm *FeatureManager) GetServiceStatus(ctx context.Context, routeID string) (*ServiceStatus, error) {
	// Get route info
	var routeName, routeType string
	err := fm.db.Pool.QueryRow(ctx,
		`SELECT name, COALESCE(route_type, 'http') FROM proxy_routes WHERE id = $1`,
		routeID).Scan(&routeName, &routeType)
	if err != nil {
		return nil, fmt.Errorf("route not found: %w", err)
	}

	status := &ServiceStatus{
		RouteID:     routeID,
		RouteName:   routeName,
		RouteType:   routeType,
		Features:    make(map[FeatureName]*ServiceFeature),
		OverallHealth: HealthStatusHealthy,
		LastUpdated: time.Now(),
	}

	// Get all features for this route
	rows, err := fm.db.Pool.Query(ctx, `
		SELECT id, route_id, feature_name, enabled, config, resource_ids,
		       status, error_message, last_health_check, health_status,
		       enabled_at, enabled_by, created_at, updated_at
		FROM service_features
		WHERE route_id = $1
	`, routeID)
	if err != nil {
		return nil, fmt.Errorf("failed to query features: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var f ServiceFeature
		var featureName string
		var configJSON, resourceJSON []byte
		var errorMsg, enabledBy *string
		var lastHealthCheck, enabledAt *time.Time
		var healthStatus, featureStatus string

		err := rows.Scan(&f.ID, &f.RouteID, &featureName, &f.Enabled,
			&configJSON, &resourceJSON, &featureStatus, &errorMsg,
			&lastHealthCheck, &healthStatus, &enabledAt, &enabledBy,
			&f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			continue
		}

		f.FeatureName = FeatureName(featureName)
		f.Status = FeatureStatus(featureStatus)
		f.HealthStatus = HealthStatus(healthStatus)
		if errorMsg != nil {
			f.ErrorMessage = *errorMsg
		}
		if lastHealthCheck != nil {
			f.LastHealthCheck = lastHealthCheck
		}
		if enabledAt != nil {
			f.EnabledAt = enabledAt
		}
		if enabledBy != nil {
			f.EnabledBy = *enabledBy
		}

		json.Unmarshal(configJSON, &f.Config)
		json.Unmarshal(resourceJSON, &f.ResourceIDs)

		status.Features[f.FeatureName] = &f

		// Update overall health
		if f.Enabled && f.HealthStatus == HealthStatusUnhealthy {
			status.OverallHealth = HealthStatusUnhealthy
		} else if f.Enabled && f.HealthStatus == HealthStatusDegraded && status.OverallHealth == HealthStatusHealthy {
			status.OverallHealth = HealthStatusDegraded
		}
	}

	return status, nil
}

// GetFeatureState returns the state of a specific feature
func (fm *FeatureManager) GetFeatureState(ctx context.Context, routeID string, feature FeatureName) (*ServiceFeature, error) {
	return fm.getFeature(ctx, routeID, feature)
}

// UpdateFeatureHealth updates the health status of a feature
func (fm *FeatureManager) UpdateFeatureHealth(ctx context.Context, routeID string, feature FeatureName, health HealthStatus, errorMsg string) error {
	_, err := fm.db.Pool.Exec(ctx, `
		UPDATE service_features
		SET health_status = $1,
		    last_health_check = NOW(),
		    error_message = CASE WHEN $2 = '' THEN NULL ELSE $2 END,
		    updated_at = NOW()
		WHERE route_id = $3 AND feature_name = $4
	`, health, errorMsg, routeID, feature)
	return err
}

// Helper methods

func (fm *FeatureManager) getOrCreateFeature(ctx context.Context, routeID string, feature FeatureName) (*ServiceFeature, error) {
	f, err := fm.getFeature(ctx, routeID, feature)
	if err == nil {
		return f, nil
	}

	// Create new feature record
	id := uuid.New().String()
	_, err = fm.db.Pool.Exec(ctx, `
		INSERT INTO service_features (id, route_id, feature_name, enabled, config, resource_ids, status, health_status)
		VALUES ($1, $2, $3, false, '{}', '{}', $4, $5)
	`, id, routeID, feature, FeatureStatusDisabled, HealthStatusUnknown)
	if err != nil {
		return nil, err
	}

	return &ServiceFeature{
		ID:          id,
		RouteID:     routeID,
		FeatureName: feature,
		Enabled:     false,
		Status:      FeatureStatusDisabled,
		HealthStatus: HealthStatusUnknown,
	}, nil
}

func (fm *FeatureManager) getFeature(ctx context.Context, routeID string, feature FeatureName) (*ServiceFeature, error) {
	var f ServiceFeature
	var featureName string
	var configJSON, resourceJSON []byte
	var errorMsg, enabledBy *string
	var lastHealthCheck, enabledAt *time.Time
	var healthStatus, featureStatus string

	err := fm.db.Pool.QueryRow(ctx, `
		SELECT id, route_id, feature_name, enabled, config, resource_ids,
		       status, error_message, last_health_check, health_status,
		       enabled_at, enabled_by, created_at, updated_at
		FROM service_features
		WHERE route_id = $1 AND feature_name = $2
	`, routeID, feature).Scan(&f.ID, &f.RouteID, &featureName, &f.Enabled,
		&configJSON, &resourceJSON, &featureStatus, &errorMsg,
		&lastHealthCheck, &healthStatus, &enabledAt, &enabledBy,
		&f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, err
	}

	f.FeatureName = FeatureName(featureName)
	f.Status = FeatureStatus(featureStatus)
	f.HealthStatus = HealthStatus(healthStatus)
	if errorMsg != nil {
		f.ErrorMessage = *errorMsg
	}
	if lastHealthCheck != nil {
		f.LastHealthCheck = lastHealthCheck
	}
	if enabledAt != nil {
		f.EnabledAt = enabledAt
	}
	if enabledBy != nil {
		f.EnabledBy = *enabledBy
	}

	json.Unmarshal(configJSON, &f.Config)
	json.Unmarshal(resourceJSON, &f.ResourceIDs)

	return &f, nil
}

func (fm *FeatureManager) updateFeatureStatus(ctx context.Context, featureID string, status FeatureStatus, errorMsg string) error {
	_, err := fm.db.Pool.Exec(ctx, `
		UPDATE service_features
		SET status = $1,
		    error_message = CASE WHEN $2 = '' THEN NULL ELSE $2 END,
		    updated_at = NOW()
		WHERE id = $3
	`, status, errorMsg, featureID)
	return err
}

func (fm *FeatureManager) validateFeatureDependencies(ctx context.Context, routeID string, feature FeatureName) error {
	switch feature {
	case FeatureBrowZer:
		// BrowZer requires Ziti to be enabled
		zitiFeature, err := fm.getFeature(ctx, routeID, FeatureZiti)
		if err != nil || !zitiFeature.Enabled {
			return fmt.Errorf("BrowZer requires Ziti to be enabled first")
		}
	}
	return nil
}

func (fm *FeatureManager) validateRouteTypeCompatibility(ctx context.Context, routeID string, feature FeatureName) error {
	var routeType string
	err := fm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(route_type, 'http') FROM proxy_routes WHERE id = $1`,
		routeID).Scan(&routeType)
	if err != nil {
		return fmt.Errorf("route not found")
	}

	switch feature {
	case FeatureGuacamole:
		// Guacamole only works with SSH, RDP, VNC, or Telnet routes
		validTypes := map[string]bool{"ssh": true, "rdp": true, "vnc": true, "telnet": true}
		if !validTypes[routeType] {
			return fmt.Errorf("Guacamole only supports SSH, RDP, VNC, or Telnet route types")
		}
	}
	return nil
}

func (fm *FeatureManager) getDependentFeatures(ctx context.Context, routeID string, feature FeatureName) ([]FeatureName, error) {
	var dependents []FeatureName

	switch feature {
	case FeatureZiti:
		// BrowZer depends on Ziti
		browzerFeature, err := fm.getFeature(ctx, routeID, FeatureBrowZer)
		if err == nil && browzerFeature.Enabled {
			dependents = append(dependents, FeatureBrowZer)
		}
	}

	return dependents, nil
}

func (fm *FeatureManager) provisionFeature(ctx context.Context, routeID string, feature FeatureName, config *FeatureConfig) (map[string]string, error) {
	resourceIDs := make(map[string]string)

	switch feature {
	case FeatureZiti:
		if fm.zitiManager == nil || !fm.zitiManager.IsInitialized() {
			return nil, fmt.Errorf("Ziti manager not available")
		}

		// Get route details
		var routeName, toURL string
		var remoteHost *string
		var remotePort *int
		err := fm.db.Pool.QueryRow(ctx,
			`SELECT name, to_url, remote_host, remote_port FROM proxy_routes WHERE id = $1`,
			routeID).Scan(&routeName, &toURL, &remoteHost, &remotePort)
		if err != nil {
			return nil, fmt.Errorf("route not found: %w", err)
		}

		// Determine host and port
		host := config.ZitiHost
		port := config.ZitiPort
		if host == "" && remoteHost != nil {
			host = *remoteHost
		}
		if port == 0 && remotePort != nil {
			port = *remotePort
		}

		// Create Ziti service
		serviceName := config.ZitiServiceName
		if serviceName == "" {
			serviceName = fmt.Sprintf("openidx-%s", routeName)
		}

		zitiService, err := fm.zitiManager.CreateServiceWithConfig(ctx, serviceName, host, port)
		if err != nil {
			return nil, fmt.Errorf("failed to create Ziti service: %w", err)
		}

		resourceIDs["ziti_service_id"] = zitiService.ID
		resourceIDs["ziti_service_name"] = zitiService.Name

		// Create Bind policy so access-proxy can host this service
		bindPolicyID, err := fm.zitiManager.CreateServicePolicy(ctx,
			fmt.Sprintf("openidx-bind-%s", serviceName),
			"Bind",
			[]string{"#" + serviceName},
			[]string{"#access-proxy-clients"})
		if err != nil {
			fm.logger.Warn("Failed to create Bind policy", zap.Error(err))
		} else {
			fm.db.Pool.Exec(ctx,
				`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles)
				 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ziti_id) DO NOTHING`,
				bindPolicyID, fmt.Sprintf("openidx-bind-%s", serviceName), "Bind",
				`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
		}

		// Create Dial policy so access-proxy can dial this service
		dialPolicyID, err := fm.zitiManager.CreateServicePolicy(ctx,
			fmt.Sprintf("openidx-dial-%s", serviceName),
			"Dial",
			[]string{"#" + serviceName},
			[]string{"#access-proxy-clients"})
		if err != nil {
			fm.logger.Warn("Failed to create Dial policy", zap.Error(err))
		} else {
			fm.db.Pool.Exec(ctx,
				`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles)
				 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ziti_id) DO NOTHING`,
				dialPolicyID, fmt.Sprintf("openidx-dial-%s", serviceName), "Dial",
				`["#`+serviceName+`"]`, `["#access-proxy-clients"]`)
		}

		// Create Service Edge Router Policy so the service is available on all edge routers
		serBody, _ := json.Marshal(map[string]interface{}{
			"name":            fmt.Sprintf("openidx-serp-%s", serviceName),
			"semantic":        "AnyOf",
			"serviceRoles":    []string{"#" + serviceName},
			"edgeRouterRoles": []string{"#all"},
		})
		_, serpStatus, serpErr := fm.zitiManager.mgmtRequest("POST", "/edge/management/v1/service-edge-router-policies", serBody)
		if serpErr != nil || (serpStatus != http.StatusCreated && serpStatus != http.StatusOK) {
			fm.logger.Warn("Failed to create service edge router policy", zap.Error(serpErr), zap.Int("status", serpStatus))
		}

		// Update proxy route with Ziti service name
		fm.db.Pool.Exec(ctx,
			"UPDATE proxy_routes SET ziti_enabled=true, ziti_service_name=$1, updated_at=NOW() WHERE id=$2",
			serviceName, routeID)

		// Host the service so it has a terminator
		if err := fm.zitiManager.HostService(serviceName, host, port); err != nil {
			fm.logger.Warn("Failed to host Ziti service (no terminator)", zap.String("service", serviceName), zap.Error(err))
		}

	case FeatureBrowZer:
		if fm.zitiManager == nil || !fm.zitiManager.IsInitialized() {
			return nil, fmt.Errorf("Ziti manager not available")
		}

		// Get the Ziti service ID for this route so we can add the browzer-enabled role attribute
		var zitiServiceID string
		err := fm.db.Pool.QueryRow(ctx,
			`SELECT zs.ziti_id FROM ziti_services zs
			 JOIN proxy_routes pr ON pr.ziti_service_name = zs.name
			 WHERE pr.id = $1`, routeID).Scan(&zitiServiceID)
		if err != nil {
			return nil, fmt.Errorf("no Ziti service found for route (enable Ziti first): %w", err)
		}

		// Add browzer-enabled role attribute to the Ziti service on the controller
		attrs, err := fm.zitiManager.GetServiceRoleAttributes(ctx, zitiServiceID)
		if err != nil {
			return nil, fmt.Errorf("failed to get service attributes: %w", err)
		}
		hasBrowzer := false
		for _, a := range attrs {
			if a == "browzer-enabled" {
				hasBrowzer = true
				break
			}
		}
		if !hasBrowzer {
			attrs = append(attrs, "browzer-enabled")
			if err := fm.zitiManager.PatchServiceRoleAttributes(ctx, zitiServiceID, attrs); err != nil {
				return nil, fmt.Errorf("failed to add browzer-enabled attribute: %w", err)
			}
		}

		resourceIDs["browzer_enabled"] = "true"
		resourceIDs["ziti_service_id"] = zitiServiceID

		// Regenerate BrowZer bootstrapper targets and router config
		if fm.browzerTargetManager != nil {
			go func() {
				bgCtx := context.Background()
				fm.browzerTargetManager.WriteBrowZerTargets(bgCtx)
				fm.browzerTargetManager.WriteBrowZerRouterConfig(bgCtx)
			}()
		}

	case FeatureGuacamole:
		if fm.guacamoleClient == nil {
			return nil, fmt.Errorf("Guacamole client not available")
		}

		// Get route details
		var routeName string
		var remoteHost *string
		var remotePort *int
		err := fm.db.Pool.QueryRow(ctx,
			`SELECT name, remote_host, remote_port FROM proxy_routes WHERE id = $1`,
			routeID).Scan(&routeName, &remoteHost, &remotePort)
		if err != nil {
			return nil, fmt.Errorf("route not found: %w", err)
		}

		// Determine connection details
		host := config.GuacamoleHost
		port := config.GuacamolePort
		protocol := config.GuacamoleProtocol
		if host == "" && remoteHost != nil {
			host = *remoteHost
		}
		if port == 0 && remotePort != nil {
			port = *remotePort
		}
		if protocol == "" {
			protocol = "ssh"
		}

		// Create Guacamole connection
		connParams := map[string]string{}
		if config.GuacamoleUsername != "" {
			connParams["username"] = config.GuacamoleUsername
		}
		if config.GuacamolePassword != "" {
			connParams["password"] = config.GuacamolePassword
		}

		connID, err := fm.guacamoleClient.CreateConnection(routeName, protocol, host, port, connParams)
		if err != nil {
			return nil, fmt.Errorf("failed to create Guacamole connection: %w", err)
		}

		resourceIDs["guacamole_connection_id"] = connID
	}

	return resourceIDs, nil
}

func (fm *FeatureManager) deprovisionFeature(ctx context.Context, routeID string, feature FeatureName, resourceIDs map[string]string) error {
	switch feature {
	case FeatureZiti:
		if fm.zitiManager != nil && fm.zitiManager.IsInitialized() {
			if serviceID, ok := resourceIDs["ziti_service_id"]; ok && serviceID != "" {
				if err := fm.zitiManager.DeleteService(ctx, serviceID); err != nil {
					fm.logger.Warn("Failed to delete Ziti service", zap.Error(err))
				}
			}
		}

	case FeatureBrowZer:
		// Remove browzer-enabled role attribute from Ziti service
		if fm.zitiManager != nil && fm.zitiManager.IsInitialized() {
			if zitiServiceID, ok := resourceIDs["ziti_service_id"]; ok && zitiServiceID != "" {
				attrs, err := fm.zitiManager.GetServiceRoleAttributes(ctx, zitiServiceID)
				if err == nil {
					filtered := make([]string, 0, len(attrs))
					for _, a := range attrs {
						if a != "browzer-enabled" {
							filtered = append(filtered, a)
						}
					}
					if err := fm.zitiManager.PatchServiceRoleAttributes(ctx, zitiServiceID, filtered); err != nil {
						fm.logger.Warn("Failed to remove browzer-enabled attribute", zap.Error(err))
					}
				}
			}
		}
		// Regenerate BrowZer bootstrapper targets and router config
		if fm.browzerTargetManager != nil {
			go func() {
				bgCtx := context.Background()
				fm.browzerTargetManager.WriteBrowZerTargets(bgCtx)
				fm.browzerTargetManager.WriteBrowZerRouterConfig(bgCtx)
			}()
		}

	case FeatureGuacamole:
		if fm.guacamoleClient != nil {
			if connID, ok := resourceIDs["guacamole_connection_id"]; ok && connID != "" {
				if err := fm.guacamoleClient.DeleteConnection(connID); err != nil {
					fm.logger.Warn("Failed to delete Guacamole connection", zap.Error(err))
				}
			}
		}
	}

	return nil
}

func (fm *FeatureManager) syncRouteFlags(ctx context.Context, routeID string, feature FeatureName, enabled bool, resourceIDs map[string]string) error {
	switch feature {
	case FeatureZiti:
		var serviceName *string
		if enabled && resourceIDs != nil {
			if name, ok := resourceIDs["ziti_service_name"]; ok {
				serviceName = &name
			}
		}
		_, err := fm.db.Pool.Exec(ctx,
			`UPDATE proxy_routes SET ziti_enabled = $1, ziti_service_name = $2, updated_at = NOW() WHERE id = $3`,
			enabled, serviceName, routeID)
		return err

	case FeatureBrowZer:
		_, err := fm.db.Pool.Exec(ctx,
			`UPDATE proxy_routes SET browzer_enabled = $1, updated_at = NOW() WHERE id = $2`,
			enabled, routeID)
		return err

	case FeatureGuacamole:
		var connID *string
		if enabled && resourceIDs != nil {
			if id, ok := resourceIDs["guacamole_connection_id"]; ok {
				connID = &id
			}
		}
		_, err := fm.db.Pool.Exec(ctx,
			`UPDATE proxy_routes SET guacamole_connection_id = $1, updated_at = NOW() WHERE id = $2`,
			connID, routeID)
		return err
	}
	return nil
}
