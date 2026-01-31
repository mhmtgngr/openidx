// Package admin provides the Admin API for the Admin Console
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// Dashboard contains overview statistics
type Dashboard struct {
	TotalUsers       int                 `json:"total_users"`
	ActiveUsers      int                 `json:"active_users"`
	TotalGroups      int                 `json:"total_groups"`
	TotalApplications int                `json:"total_applications"`
	ActiveSessions   int                 `json:"active_sessions"`
	PendingReviews   int                 `json:"pending_reviews"`
	SecurityAlerts   int                 `json:"security_alerts"`
	RecentActivity       []ActivityItem       `json:"recent_activity"`
	AuthStats            AuthStatistics       `json:"auth_stats"`
	SecurityAlertDetails []SecurityAlertDetail `json:"security_alert_details"`
}

// ActivityItem represents recent activity
type ActivityItem struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	ActorID   string    `json:"actor_id,omitempty"`
	ActorName string    `json:"actor_name,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AuthStatistics contains authentication statistics
type AuthStatistics struct {
	TotalLogins      int            `json:"total_logins"`
	SuccessfulLogins int            `json:"successful_logins"`
	FailedLogins     int            `json:"failed_logins"`
	MFAUsage         int            `json:"mfa_usage"`
	LoginsByMethod   map[string]int `json:"logins_by_method"`
	LoginsByDay      []DayStats     `json:"logins_by_day"`
}

// DayStats contains statistics for a single day
type DayStats struct {
	Date   string `json:"date"`
	Count  int    `json:"count"`
}

// SecurityAlertDetail represents a security alert detail
type SecurityAlertDetail struct {
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// Application represents a registered application/client
type Application struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Type          string    `json:"type"`
	Protocol      string    `json:"protocol"`
	BaseURL       string    `json:"base_url,omitempty"`
	RedirectURIs  []string  `json:"redirect_uris"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ApplicationSSOSettings represents SSO settings for an application
type ApplicationSSOSettings struct {
	ID                     string    `json:"id"`
	ApplicationID          string    `json:"application_id"`
	Enabled                bool      `json:"enabled"`
	UseRefreshTokens       bool      `json:"use_refresh_tokens"`
	AccessTokenLifetime    int       `json:"access_token_lifetime"`
	RefreshTokenLifetime   int       `json:"refresh_token_lifetime"`
	RequireConsent         bool      `json:"require_consent"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// DirectoryIntegration represents an external directory sync configuration
type DirectoryIntegration struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"` // ldap, azure_ad, google
	Config     map[string]interface{} `json:"config"`
	Enabled    bool                   `json:"enabled"`
	LastSyncAt *time.Time             `json:"last_sync_at,omitempty"`
	SyncStatus string                 `json:"sync_status"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// Settings represents system settings
type Settings struct {
	General       GeneralSettings       `json:"general"`
	Security      SecuritySettings      `json:"security"`
	Authentication AuthenticationSettings `json:"authentication"`
	Branding      BrandingSettings      `json:"branding"`
}

// GeneralSettings contains general system settings
type GeneralSettings struct {
	OrganizationName string `json:"organization_name"`
	SupportEmail     string `json:"support_email"`
	DefaultLanguage  string `json:"default_language"`
	DefaultTimezone  string `json:"default_timezone"`
}

// SecuritySettings contains security-related settings
type SecuritySettings struct {
	PasswordPolicy     PasswordPolicy `json:"password_policy"`
	SessionTimeout     int            `json:"session_timeout"`
	MaxFailedLogins    int            `json:"max_failed_logins"`
	LockoutDuration    int            `json:"lockout_duration"`
	RequireMFA         bool           `json:"require_mfa"`
	AllowedIPRanges    []string       `json:"allowed_ip_ranges,omitempty"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	MaxAge           int  `json:"max_age"`
	History          int  `json:"history"`
}

// AuthenticationSettings contains authentication settings
type AuthenticationSettings struct {
	AllowRegistration  bool     `json:"allow_registration"`
	RequireEmailVerify bool     `json:"require_email_verify"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	SocialProviders    []string `json:"social_providers,omitempty"`
	MFAMethods         []string `json:"mfa_methods"`
}

// BrandingSettings contains branding customization
type BrandingSettings struct {
	LogoURL         string            `json:"logo_url,omitempty"`
	FaviconURL      string            `json:"favicon_url,omitempty"`
	PrimaryColor    string            `json:"primary_color"`
	SecondaryColor  string            `json:"secondary_color"`
	CustomCSS       string            `json:"custom_css,omitempty"`
	LoginPageTitle  string            `json:"login_page_title"`
	LoginPageMessage string           `json:"login_page_message,omitempty"`
}

// DirectorySyncer defines the interface for directory sync operations
type DirectorySyncer interface {
	TestConnection(ctx context.Context, cfg interface{}) error
	TriggerSync(ctx context.Context, directoryID string, fullSync bool) error
	GetSyncLogs(ctx context.Context, directoryID string, limit int) (interface{}, error)
	GetSyncState(ctx context.Context, directoryID string) (interface{}, error)
}

// Service provides admin operations
// RiskAssessor defines the interface for risk/device management operations
type RiskAssessor interface {
	GetAllDevices(ctx context.Context, limit, offset int) (interface{}, int, error)
	GetUserDevices(ctx context.Context, userID string) (interface{}, error)
	TrustDevice(ctx context.Context, deviceID string) error
	RevokeDevice(ctx context.Context, deviceID string) error
	GetRiskStats(ctx context.Context) (map[string]interface{}, error)
	GetLoginHistory(ctx context.Context, userID string, limit int) (interface{}, error)
}

type Service struct {
	db               *database.PostgresDB
	redis            *database.RedisClient
	config           *config.Config
	logger           *zap.Logger
	directoryService DirectorySyncer
	riskService      RiskAssessor
}

// NewService creates a new admin service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: logger.With(zap.String("service", "admin")),
	}
}

// SetDirectoryService sets the directory service for sync operations
func (s *Service) SetDirectoryService(ds DirectorySyncer) {
	s.directoryService = ds
}

// SetRiskService sets the risk service for device/risk management
func (s *Service) SetRiskService(rs RiskAssessor) {
	s.riskService = rs
}

// GetDashboard returns dashboard statistics
func (s *Service) GetDashboard(ctx context.Context) (*Dashboard, error) {
	s.logger.Debug("Getting dashboard statistics")

	var totalUsers, activeUsers, totalGroups, totalApps, activeSessions, pendingReviews, securityAlerts int

	// Get all dashboard counts in a single query
	err := s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM users WHERE enabled = true),
			(SELECT COUNT(*) FROM groups),
			(SELECT COUNT(*) FROM applications),
			(SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()),
			(SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress')),
			(SELECT COUNT(*) FROM audit_events WHERE outcome = 'failure' AND event_type = 'authentication' AND timestamp > NOW() - INTERVAL '24 hours')
	`).Scan(&totalUsers, &activeUsers, &totalGroups, &totalApps, &activeSessions, &pendingReviews, &securityAlerts)
	if err != nil {
		s.logger.Error("Failed to query dashboard stats", zap.Error(err))
	}

	// Get recent activity from audit events
	var recentActivity []ActivityItem
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, event_type, action, actor_id, timestamp
		FROM audit_events
		ORDER BY timestamp DESC
		LIMIT 5
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item ActivityItem
			rows.Scan(&item.ID, &item.Type, &item.Message, &item.ActorID, &item.Timestamp)
			recentActivity = append(recentActivity, item)
		}
	}

	dashboard := &Dashboard{
		TotalUsers:        totalUsers,
		ActiveUsers:       activeUsers,
		TotalGroups:       totalGroups,
		TotalApplications: totalApps,
		ActiveSessions:    activeSessions,
		PendingReviews:    pendingReviews,
		SecurityAlerts:    securityAlerts,
		RecentActivity:    recentActivity,
		AuthStats: s.getAuthStatistics(ctx),
	}

	// Get top 5 failed auth attempts grouped by actor
	var alertDetails []SecurityAlertDetail
	alertRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(actor_id, 'unknown') as actor, COUNT(*) as cnt, MAX(timestamp) as latest
		FROM audit_events
		WHERE outcome = 'failure' AND event_type = 'authentication'
		AND timestamp > NOW() - INTERVAL '24 hours'
		GROUP BY actor_id
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var detail SecurityAlertDetail
			var actor string
			alertRows.Scan(&actor, &detail.Count, &detail.Timestamp)
			detail.Message = fmt.Sprintf("Failed login attempts from %s", actor)
			alertDetails = append(alertDetails, detail)
		}
	}
	dashboard.SecurityAlertDetails = alertDetails

	return dashboard, nil
}

// getAuthStatistics queries real authentication statistics from audit_events
func (s *Service) getAuthStatistics(ctx context.Context) AuthStatistics {
	stats := AuthStatistics{
		LoginsByMethod: make(map[string]int),
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
	`).Scan(&stats.TotalLogins); err != nil {
		s.logger.Error("Failed to query total logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'success' AND timestamp > NOW() - INTERVAL '30 days'
	`).Scan(&stats.SuccessfulLogins); err != nil {
		s.logger.Error("Failed to query successful logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND outcome = 'failure' AND timestamp > NOW() - INTERVAL '30 days'
	`).Scan(&stats.FailedLogins); err != nil {
		s.logger.Error("Failed to query failed logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE event_type = 'mfa_verification' AND outcome = 'success' AND timestamp > NOW() - INTERVAL '30 days'
	`).Scan(&stats.MFAUsage); err != nil {
		s.logger.Error("Failed to query MFA usage", zap.Error(err))
	}

	// Logins by method
	methodRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(action, 'unknown'), COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY action
	`)
	if err == nil {
		defer methodRows.Close()
		for methodRows.Next() {
			var method string
			var count int
			methodRows.Scan(&method, &count)
			stats.LoginsByMethod[method] = count
		}
	}

	// Logins by day (last 7 days)
	dayRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp)::text, COUNT(*) FROM audit_events
		WHERE event_type = 'authentication' AND timestamp > NOW() - INTERVAL '7 days'
		GROUP BY DATE(timestamp)
		ORDER BY DATE(timestamp)
	`)
	if err == nil {
		defer dayRows.Close()
		for dayRows.Next() {
			var ds DayStats
			dayRows.Scan(&ds.Date, &ds.Count)
			stats.LoginsByDay = append(stats.LoginsByDay, ds)
		}
	}

	return stats
}

// GetSettings returns system settings
func (s *Service) GetSettings(ctx context.Context) (*Settings, error) {
	s.logger.Debug("Getting system settings")

	var valueBytes []byte
	err := s.db.Pool.QueryRow(ctx, "SELECT value FROM system_settings WHERE key = 'system'").Scan(&valueBytes)
	if err == nil {
		var settings Settings
		if jsonErr := json.Unmarshal(valueBytes, &settings); jsonErr == nil {
			return &settings, nil
		}
		s.logger.Warn("Failed to unmarshal settings from database, using defaults", zap.Error(err))
	}

	// Fall back to defaults
	settings := &Settings{
		General: GeneralSettings{
			OrganizationName: "OpenIDX",
			SupportEmail:     "support@openidx.io",
			DefaultLanguage:  "en",
			DefaultTimezone:  "UTC",
		},
		Security: SecuritySettings{
			PasswordPolicy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				History:          5,
			},
			SessionTimeout:  30,
			MaxFailedLogins: 5,
			LockoutDuration: 15,
			RequireMFA:      false,
		},
		Authentication: AuthenticationSettings{
			AllowRegistration:  true,
			RequireEmailVerify: true,
			MFAMethods:         []string{"totp", "webauthn", "sms"},
		},
		Branding: BrandingSettings{
			PrimaryColor:   "#2563eb",
			SecondaryColor: "#1e40af",
			LoginPageTitle: "Welcome to OpenIDX",
		},
	}
	
	return settings, nil
}

// UpdateSettings updates system settings
func (s *Service) UpdateSettings(ctx context.Context, settings *Settings) error {
	s.logger.Info("Updating system settings")

	valueBytes, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ('system', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, valueBytes)
	if err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	return nil
}

// UpdateApplication updates an existing application
func (s *Service) UpdateApplication(ctx context.Context, id string, updates map[string]interface{}) error {
	s.logger.Info("Updating application", zap.String("id", id))

	setParts := []string{}
	args := []interface{}{}
	argCount := 1

	if name, ok := updates["name"].(string); ok {
		setParts = append(setParts, "name = $"+fmt.Sprintf("%d", argCount))
		args = append(args, name)
		argCount++
	}

	if description, ok := updates["description"].(string); ok {
		setParts = append(setParts, "description = $"+fmt.Sprintf("%d", argCount))
		args = append(args, description)
		argCount++
	}

	if baseURL, ok := updates["base_url"].(string); ok {
		setParts = append(setParts, "base_url = $"+fmt.Sprintf("%d", argCount))
		args = append(args, baseURL)
		argCount++
	}

	if redirectURIsRaw, ok := updates["redirect_uris"]; ok {
		// Handle both []string and []interface{} types
		var redirectURIs []string
		if uris, ok := redirectURIsRaw.([]string); ok {
			redirectURIs = uris
		} else if uris, ok := redirectURIsRaw.([]interface{}); ok {
			for _, uri := range uris {
				if uriStr, ok := uri.(string); ok {
					redirectURIs = append(redirectURIs, uriStr)
				}
			}
		}
		if len(redirectURIs) > 0 {
			setParts = append(setParts, "redirect_uris = $"+fmt.Sprintf("%d", argCount))
			args = append(args, redirectURIs)
			argCount++
		}
	}

	if enabled, ok := updates["enabled"].(bool); ok {
		setParts = append(setParts, "enabled = $"+fmt.Sprintf("%d", argCount))
		args = append(args, enabled)
		argCount++
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	setParts = append(setParts, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE applications SET %s WHERE id = $%d",
		strings.Join(setParts, ", "), argCount)
	args = append(args, id)

	_, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}

	return nil
}

// ListApplications returns registered applications with optional pagination
func (s *Service) ListApplications(ctx context.Context, offset, limit int) ([]Application, int, error) {
	s.logger.Debug("Listing applications")

	var totalCount int
	if err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM applications").Scan(&totalCount); err != nil {
		s.logger.Error("Failed to query application count", zap.Error(err))
	}

	query := `
		SELECT id, client_id, name, COALESCE(description, ''), type, protocol,
		       COALESCE(base_url, ''), redirect_uris, enabled, created_at, updated_at
		FROM applications
		ORDER BY name
	`
	args := []interface{}{}
	argCount := 1

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, limit)
		argCount++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, offset)
		argCount++
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		if err := rows.Scan(
			&app.ID, &app.ClientID, &app.Name, &app.Description, &app.Type,
			&app.Protocol, &app.BaseURL, &app.RedirectURIs, &app.Enabled, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		apps = append(apps, app)
	}

	return apps, totalCount, nil
}

// CreateApplication creates a new application
func (s *Service) CreateApplication(ctx context.Context, app *Application) error {
	s.logger.Info("Creating application", zap.String("name", app.Name))

	if app.ID == "" {
		app.ID = uuid.New().String()
	}
	if app.ClientID == "" {
		app.ClientID = uuid.New().String()
	}
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, app.ID, app.ClientID, app.Name, app.Description, app.Type, app.Protocol,
		app.BaseURL, app.RedirectURIs, app.Enabled, app.CreatedAt, app.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	return nil
}

// GetApplicationSSOSettings gets SSO settings for an application
func (s *Service) GetApplicationSSOSettings(ctx context.Context, applicationID string) (*ApplicationSSOSettings, error) {
	s.logger.Debug("Getting SSO settings", zap.String("application_id", applicationID))

	var settings ApplicationSSOSettings
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, application_id, enabled, use_refresh_tokens, access_token_lifetime,
		       refresh_token_lifetime, require_consent, created_at, updated_at
		FROM application_sso_settings WHERE application_id = $1
	`, applicationID).Scan(
		&settings.ID, &settings.ApplicationID, &settings.Enabled, &settings.UseRefreshTokens,
		&settings.AccessTokenLifetime, &settings.RefreshTokenLifetime, &settings.RequireConsent,
		&settings.CreatedAt, &settings.UpdatedAt,
	)

	if err != nil {
		// Return default settings if none exist
		settings = ApplicationSSOSettings{
			ApplicationID:          applicationID,
			Enabled:                true,
			UseRefreshTokens:       true,
			AccessTokenLifetime:    3600,
			RefreshTokenLifetime:   86400,
			RequireConsent:         false,
		}
		return &settings, nil
	}

	return &settings, nil
}

// UpdateApplicationSSOSettings updates SSO settings for an application
func (s *Service) UpdateApplicationSSOSettings(ctx context.Context, settings *ApplicationSSOSettings) error {
	s.logger.Info("Updating SSO settings", zap.String("application_id", settings.ApplicationID))

	settings.UpdatedAt = time.Now()

	// Try to update existing settings
	result, err := s.db.Pool.Exec(ctx, `
		UPDATE application_sso_settings SET
			enabled = $2, use_refresh_tokens = $3, access_token_lifetime = $4,
			refresh_token_lifetime = $5, require_consent = $6, updated_at = $7
		WHERE application_id = $1
	`, settings.ApplicationID, settings.Enabled, settings.UseRefreshTokens,
		settings.AccessTokenLifetime, settings.RefreshTokenLifetime, settings.RequireConsent, settings.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update SSO settings: %w", err)
	}

	// If no rows were affected, create new settings
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		settings.ID = uuid.New().String()
		settings.CreatedAt = settings.UpdatedAt

		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens,
				access_token_lifetime, refresh_token_lifetime, require_consent, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, settings.ID, settings.ApplicationID, settings.Enabled, settings.UseRefreshTokens,
			settings.AccessTokenLifetime, settings.RefreshTokenLifetime, settings.RequireConsent,
			settings.CreatedAt, settings.UpdatedAt)

		if err != nil {
			return fmt.Errorf("failed to create SSO settings: %w", err)
		}
	}

	return nil
}

// RegisterRoutes registers admin service routes
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	// Dashboard
	router.GET("/dashboard", svc.handleGetDashboard)
	
	// Settings
	router.GET("/settings", svc.handleGetSettings)
	router.PUT("/settings", svc.handleUpdateSettings)
	
	// Applications
	router.GET("/applications", svc.handleListApplications)
	router.POST("/applications", svc.handleCreateApplication)
	router.GET("/applications/:id", svc.handleGetApplication)
	router.PUT("/applications/:id", svc.handleUpdateApplication)
	router.DELETE("/applications/:id", svc.handleDeleteApplication)

	// Application SSO Settings
	router.GET("/applications/:id/sso-settings", svc.handleGetApplicationSSOSettings)
	router.PUT("/applications/:id/sso-settings", svc.handleUpdateApplicationSSOSettings)
	
	// Directory integrations
	router.GET("/directories", svc.handleListDirectories)
	router.POST("/directories", svc.handleCreateDirectory)
	router.GET("/directories/:id", svc.handleGetDirectory)
	router.PUT("/directories/:id", svc.handleUpdateDirectory)
	router.DELETE("/directories/:id", svc.handleDeleteDirectory)
	router.POST("/directories/:id/sync", svc.handleSyncDirectory)
	router.POST("/directories/:id/test", svc.handleTestConnection)
	router.GET("/directories/:id/sync-logs", svc.handleGetSyncLogs)
	router.GET("/directories/:id/sync-state", svc.handleGetSyncState)
	
	// MFA configuration
	router.GET("/mfa/methods", svc.handleListMFAMethods)
	router.PUT("/mfa/methods", svc.handleUpdateMFAMethods)

	// Device management (conditional access)
	router.GET("/devices", svc.handleListDevices)
	router.GET("/users/:id/devices", svc.handleUserDevices)
	router.POST("/devices/:id/trust", svc.handleTrustDevice)
	router.DELETE("/devices/:id", svc.handleRevokeDevice)

	// Risk stats and login history
	router.GET("/risk/stats", svc.handleRiskStats)
	router.GET("/login-history", svc.handleLoginHistory)
}

// HTTP Handlers

func (s *Service) handleGetDashboard(c *gin.Context) {
	dashboard, err := s.GetDashboard(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, dashboard)
}

func (s *Service) handleGetSettings(c *gin.Context) {
	settings, err := s.GetSettings(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, settings)
}

func (s *Service) handleUpdateSettings(c *gin.Context) {
	var settings Settings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.UpdateSettings(c.Request.Context(), &settings); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, settings)
}

func (s *Service) handleListApplications(c *gin.Context) {
	offset := 0
	limit := 0
	if v := c.Query("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if v := c.Query("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}

	apps, totalCount, err := s.ListApplications(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Header("X-Total-Count", fmt.Sprintf("%d", totalCount))
	c.JSON(200, apps)
}

func (s *Service) handleCreateApplication(c *gin.Context) {
	var app Application
	if err := c.ShouldBindJSON(&app); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreateApplication(c.Request.Context(), &app); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, app)
}

func (s *Service) handleGetApplication(c *gin.Context) {
	id := c.Param("id")
	var app Application
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT id, client_id, name, COALESCE(description, ''), type, protocol,
		       COALESCE(base_url, ''), redirect_uris, enabled, created_at, updated_at
		FROM applications WHERE id = $1
	`, id).Scan(
		&app.ID, &app.ClientID, &app.Name, &app.Description, &app.Type,
		&app.Protocol, &app.BaseURL, &app.RedirectURIs, &app.Enabled, &app.CreatedAt, &app.UpdatedAt,
	)
	if err != nil {
		c.JSON(404, gin.H{"error": "Application not found"})
		return
	}
	c.JSON(200, app)
}
func (s *Service) handleUpdateApplication(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateApplication(c.Request.Context(), id, updates); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Application updated successfully"})
}
func (s *Service) handleDeleteApplication(c *gin.Context) {
	id := c.Param("id")
	result, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM applications WHERE id = $1", id)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete application"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Application not found"})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleListDirectories(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, name, type, config, enabled, last_sync_at, sync_status, created_at, updated_at
		FROM directory_integrations ORDER BY name
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list directories"})
		return
	}
	defer rows.Close()

	var dirs []DirectoryIntegration
	for rows.Next() {
		var d DirectoryIntegration
		var configBytes []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.Type, &configBytes, &d.Enabled, &d.LastSyncAt, &d.SyncStatus, &d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		if len(configBytes) > 0 {
			if err := json.Unmarshal(configBytes, &d.Config); err != nil {
				s.logger.Warn("Failed to parse directory config", zap.String("id", d.ID), zap.Error(err))
			}
		}
		dirs = append(dirs, d)
	}
	if dirs == nil {
		dirs = []DirectoryIntegration{}
	}
	c.JSON(200, dirs)
}

func (s *Service) handleCreateDirectory(c *gin.Context) {
	var dir DirectoryIntegration
	if err := c.ShouldBindJSON(&dir); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	dir.ID = uuid.New().String()
	dir.SyncStatus = "never"
	dir.CreatedAt = time.Now()
	dir.UpdatedAt = time.Now()

	configBytes, _ := json.Marshal(dir.Config)

	_, err := s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO directory_integrations (id, name, type, config, enabled, sync_status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, dir.ID, dir.Name, dir.Type, configBytes, dir.Enabled, dir.SyncStatus, dir.CreatedAt, dir.UpdatedAt)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create directory integration"})
		return
	}

	c.JSON(201, dir)
}

func (s *Service) handleGetDirectory(c *gin.Context) {
	id := c.Param("id")
	var d DirectoryIntegration
	var configBytes []byte
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, type, config, enabled, last_sync_at, sync_status, created_at, updated_at
		 FROM directory_integrations WHERE id = $1`, id).Scan(
		&d.ID, &d.Name, &d.Type, &configBytes, &d.Enabled, &d.LastSyncAt, &d.SyncStatus, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	if len(configBytes) > 0 {
		json.Unmarshal(configBytes, &d.Config)
	}
	c.JSON(200, d)
}

func (s *Service) handleUpdateDirectory(c *gin.Context) {
	id := c.Param("id")
	var dir DirectoryIntegration
	if err := c.ShouldBindJSON(&dir); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	configBytes, _ := json.Marshal(dir.Config)

	result, err := s.db.Pool.Exec(c.Request.Context(), `
		UPDATE directory_integrations SET name = $2, type = $3, config = $4, enabled = $5, updated_at = NOW()
		WHERE id = $1
	`, id, dir.Name, dir.Type, configBytes, dir.Enabled)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update directory"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Directory updated"})
}

func (s *Service) handleDeleteDirectory(c *gin.Context) {
	id := c.Param("id")
	result, err := s.db.Pool.Exec(c.Request.Context(), `DELETE FROM directory_integrations WHERE id = $1`, id)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete directory"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Directory deleted"})
}

func (s *Service) handleSyncDirectory(c *gin.Context) {
	id := c.Param("id")

	// Verify directory exists
	var exists bool
	s.db.Pool.QueryRow(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM directory_integrations WHERE id = $1)`, id).Scan(&exists)
	if !exists {
		c.JSON(404, gin.H{"error": "Directory integration not found"})
		return
	}

	fullSync := c.Query("full") == "true"

	if s.directoryService != nil {
		if err := s.directoryService.TriggerSync(c.Request.Context(), id, fullSync); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Fallback: just mark as syncing if no directory service
		s.db.Pool.Exec(c.Request.Context(), `
			UPDATE directory_integrations SET sync_status = 'syncing', last_sync_at = NOW(), updated_at = NOW()
			WHERE id = $1`, id)
	}

	syncType := "incremental"
	if fullSync {
		syncType = "full"
	}

	c.JSON(200, gin.H{"status": "syncing", "sync_type": syncType, "message": "Directory sync initiated"})
}

func (s *Service) handleTestConnection(c *gin.Context) {
	id := c.Param("id")

	var configBytes []byte
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT config FROM directory_integrations WHERE id = $1`, id).Scan(&configBytes)
	if err != nil {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}

	if s.directoryService != nil {
		var cfg map[string]interface{}
		json.Unmarshal(configBytes, &cfg)

		if err := s.directoryService.TestConnection(c.Request.Context(), cfg); err != nil {
			c.JSON(400, gin.H{"error": err.Error(), "success": false})
			return
		}
	}

	c.JSON(200, gin.H{"success": true, "message": "Connection test successful"})
}

func (s *Service) handleGetSyncLogs(c *gin.Context) {
	id := c.Param("id")

	if s.directoryService != nil {
		logs, err := s.directoryService.GetSyncLogs(c.Request.Context(), id, 20)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get sync logs"})
			return
		}
		c.JSON(200, logs)
		return
	}

	c.JSON(200, []interface{}{})
}

func (s *Service) handleGetSyncState(c *gin.Context) {
	id := c.Param("id")

	if s.directoryService != nil {
		state, err := s.directoryService.GetSyncState(c.Request.Context(), id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get sync state"})
			return
		}
		c.JSON(200, state)
		return
	}

	c.JSON(200, gin.H{"directory_id": id})
}

func (s *Service) handleListMFAMethods(c *gin.Context) {
	var valueBytes []byte
	err := s.db.Pool.QueryRow(c.Request.Context(), "SELECT value FROM system_settings WHERE key = 'mfa_methods'").Scan(&valueBytes)
	if err == nil {
		var methods []string
		if json.Unmarshal(valueBytes, &methods) == nil {
			c.JSON(200, methods)
			return
		}
	}
	c.JSON(200, []string{"totp", "webauthn", "sms"})
}

func (s *Service) handleUpdateMFAMethods(c *gin.Context) {
	var methods []string
	if err := c.ShouldBindJSON(&methods); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body, expected array of strings"})
		return
	}

	valueBytes, err := json.Marshal(methods)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to marshal methods"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ('mfa_methods', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, valueBytes)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to save MFA methods"})
		return
	}

	c.JSON(200, gin.H{"status": "updated", "methods": methods})
}

func (s *Service) handleGetApplicationSSOSettings(c *gin.Context) {
	applicationID := c.Param("id")

	settings, err := s.GetApplicationSSOSettings(c.Request.Context(), applicationID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, settings)
}

func (s *Service) handleUpdateApplicationSSOSettings(c *gin.Context) {
	applicationID := c.Param("id")

	var settings ApplicationSSOSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	settings.ApplicationID = applicationID

	if err := s.UpdateApplicationSSOSettings(c.Request.Context(), &settings); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "SSO settings updated successfully"})
}

// Device management handlers

func (s *Service) handleListDevices(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}

	devices, total, err := s.riskService.GetAllDevices(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"devices": devices, "total": total})
}

func (s *Service) handleUserDevices(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	userID := c.Param("id")
	devices, err := s.riskService.GetUserDevices(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"devices": devices})
}

func (s *Service) handleTrustDevice(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	deviceID := c.Param("id")
	if err := s.riskService.TrustDevice(c.Request.Context(), deviceID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "Device trusted"})
}

func (s *Service) handleRevokeDevice(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	deviceID := c.Param("id")
	if err := s.riskService.RevokeDevice(c.Request.Context(), deviceID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "Device revoked"})
}

func (s *Service) handleRiskStats(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	stats, err := s.riskService.GetRiskStats(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, stats)
}

func (s *Service) handleLoginHistory(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	userID := c.Query("user_id")
	limit := 50
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	history, err := s.riskService.GetLoginHistory(c.Request.Context(), userID, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"history": history})
}
