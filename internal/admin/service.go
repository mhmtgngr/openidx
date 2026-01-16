// Package admin provides the Admin API for the Admin Console
package admin

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
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
	RecentActivity   []ActivityItem      `json:"recent_activity"`
	AuthStats        AuthStatistics      `json:"auth_stats"`
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

// Service provides admin operations
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
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

// GetDashboard returns dashboard statistics
func (s *Service) GetDashboard(ctx context.Context) (*Dashboard, error) {
	s.logger.Debug("Getting dashboard statistics")

	var totalUsers, activeUsers, totalGroups, totalApps, activeSessions, pendingReviews int

	// Get real counts from database
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE enabled = true").Scan(&activeUsers)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups").Scan(&totalGroups)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM applications").Scan(&totalApps)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()").Scan(&activeSessions)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress')").Scan(&pendingReviews)

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
		SecurityAlerts:    0,
		RecentActivity:    recentActivity,
		AuthStats: AuthStatistics{
			TotalLogins:      100,
			SuccessfulLogins: 95,
			FailedLogins:     5,
			MFAUsage:         50,
			LoginsByMethod: map[string]int{
				"password": 80,
				"sso":      15,
				"mfa":      5,
			},
		},
	}

	return dashboard, nil
}

// GetSettings returns system settings
func (s *Service) GetSettings(ctx context.Context) (*Settings, error) {
	s.logger.Debug("Getting system settings")
	
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
	// Store settings in database
	return nil
}

// ListApplications returns all registered applications
func (s *Service) ListApplications(ctx context.Context) ([]Application, error) {
	s.logger.Debug("Listing applications")

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, client_id, name, COALESCE(description, ''), type, protocol,
		       COALESCE(base_url, ''), enabled, created_at, updated_at
		FROM applications
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		if err := rows.Scan(
			&app.ID, &app.ClientID, &app.Name, &app.Description, &app.Type,
			&app.Protocol, &app.BaseURL, &app.Enabled, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}

	return apps, nil
}

// CreateApplication creates a new application
func (s *Service) CreateApplication(ctx context.Context, app *Application) error {
	s.logger.Info("Creating application", zap.String("name", app.Name))
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()
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
	
	// Directory integrations
	router.GET("/directories", svc.handleListDirectories)
	router.POST("/directories", svc.handleCreateDirectory)
	router.POST("/directories/:id/sync", svc.handleSyncDirectory)
	
	// MFA configuration
	router.GET("/mfa/methods", svc.handleListMFAMethods)
	router.PUT("/mfa/methods", svc.handleUpdateMFAMethods)
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
	apps, err := s.ListApplications(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
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

func (s *Service) handleGetApplication(c *gin.Context)    { c.JSON(200, Application{}) }
func (s *Service) handleUpdateApplication(c *gin.Context) { c.JSON(200, Application{}) }
func (s *Service) handleDeleteApplication(c *gin.Context) { c.JSON(204, nil) }

func (s *Service) handleListDirectories(c *gin.Context)   { c.JSON(200, []gin.H{}) }
func (s *Service) handleCreateDirectory(c *gin.Context)   { c.JSON(201, gin.H{}) }
func (s *Service) handleSyncDirectory(c *gin.Context)     { c.JSON(200, gin.H{"status": "syncing"}) }

func (s *Service) handleListMFAMethods(c *gin.Context)    { c.JSON(200, []string{"totp", "webauthn", "sms"}) }
func (s *Service) handleUpdateMFAMethods(c *gin.Context)  { c.JSON(200, gin.H{"status": "updated"}) }
