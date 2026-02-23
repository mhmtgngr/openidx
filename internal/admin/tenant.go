// Package admin provides multi-tenancy management for the admin console
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Tenant represents a multi-tenant organization
type Tenant struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Domain    string          `json:"domain"`
	Plan      string          `json:"plan"` // free, pro, enterprise
	Config    TenantConfig    `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// TenantConfig contains tenant-specific configuration
type TenantConfig struct {
	Branding           TenantBranding       `json:"branding"`
	Security           TenantSecurity       `json:"security"`
	Features           TenantFeatures       `json:"features"`
	Limits             TenantLimits         `json:"limits"`
	PasswordPolicy     PasswordPolicy       `json:"password_policy"`
	SessionPolicy      SessionPolicy        `json:"session_policy"`
	MFAPolicy          TenantMFAPolicy      `json:"mfa_policy"`
	RateLimit          RateLimitConfig      `json:"rate_limit"`
}

// TenantBranding contains branding customization for a tenant
type TenantBranding struct {
	LogoURL         string `json:"logo_url,omitempty"`
	FaviconURL      string `json:"favicon_url,omitempty"`
	PrimaryColor    string `json:"primary_color"`
	SecondaryColor  string `json:"secondary_color"`
	LoginTitle      string `json:"login_title"`
	LoginMessage    string `json:"login_message,omitempty"`
}

// TenantSecurity contains security settings for a tenant
type TenantSecurity struct {
	AllowlistedDomains []string `json:"allowlisted_domains,omitempty"`
	BlockedCountries   []string `json:"blocked_countries,omitempty"`
}

// TenantFeatures contains feature flags for a tenant
type TenantFeatures struct {
	SCIMProvisioning bool `json:"scim_provisioning"`
	SAMLSSO          bool `json:"saml_sso"`
	APIAccess        bool `json:"api_access"`
	AuditLogRetention int  `json:"audit_log_retention_days"`
}

// TenantLimits contains resource limits for a tenant
type TenantLimits struct {
	MaxUsers      int `json:"max_users"`
	MaxGroups     int `json:"max_groups"`
	MaxApps       int `json:"max_apps"`
	MaxAdmins     int `json:"max_admins"`
	MaxAPIKeys    int `json:"max_api_keys"`
}

// SessionPolicy defines session management rules
type SessionPolicy struct {
	TimeoutMinutes  int `json:"timeout_minutes"`
	MaxConcurrent   int `json:"max_concurrent"`
}

// TenantMFAPolicy defines MFA requirements for a tenant
type TenantMFAPolicy struct {
	RequiredForRoles []string `json:"required_for_roles"`
	AllowedMethods   []string `json:"allowed_methods"` // totp, sms, email, webhook
}

// RateLimitConfig defines rate limiting rules
type RateLimitConfig struct {
	PerIP  int `json:"per_ip"`
	PerUser int `json:"per_user"`
}

// TenantResponse is the response format for tenant queries
type TenantResponse struct {
	Data       []Tenant `json:"data"`
	Total      int      `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
}

// CreateTenantRequest is the request format for creating a tenant
type CreateTenantRequest struct {
	Name   string       `json:"name" binding:"required,min=2,max=100"`
	Domain string       `json:"domain" binding:"required,min=3,max=255"`
	Plan   string       `json:"plan" binding:"required,oneof=free pro enterprise"`
	Config TenantConfig `json:"config"`
}

// UpdateTenantRequest is the request format for updating a tenant
type UpdateTenantRequest struct {
	Name   *string       `json:"name" binding:"omitempty,min=2,max=100"`
	Domain *string       `json:"domain" binding:"omitempty,min=3,max=255"`
	Plan   *string       `json:"plan" binding:"omitempty,oneof=free pro enterprise"`
	Config *TenantConfig `json:"config"`
}

// ListTenants retrieves all tenants with pagination
func (s *Service) ListTenants(ctx context.Context, page, pageSize int) (*TenantResponse, error) {
	offset := (page - 1) * pageSize

	// Get total count
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM tenants").Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count tenants: %w", err)
	}

	// Get paginated tenants
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, domain, plan, config, created_at, updated_at
		FROM tenants
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		var configJSON []byte
		err := rows.Scan(&t.ID, &t.Name, &t.Domain, &t.Plan, &configJSON, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			s.logger.Warn("Failed to scan tenant row", zap.Error(err))
			continue
		}
		if len(configJSON) > 0 {
			_ = json.Unmarshal(configJSON, &t.Config)
		} else {
			t.Config = DefaultTenantConfig()
		}
		tenants = append(tenants, t)
	}

	if tenants == nil {
		tenants = []Tenant{}
	}

	return &TenantResponse{
		Data:     tenants,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// GetTenant retrieves a tenant by ID
func (s *Service) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	var configJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, config, created_at, updated_at
		FROM tenants WHERE id = $1
	`, id).Scan(&t.ID, &t.Name, &t.Domain, &t.Plan, &configJSON, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &t.Config); err != nil {
			s.logger.Warn("Failed to unmarshal tenant config", zap.Error(err))
			t.Config = DefaultTenantConfig()
		}
	} else {
		t.Config = DefaultTenantConfig()
	}

	return &t, nil
}

// GetTenantByDomain retrieves a tenant by domain
func (s *Service) GetTenantByDomain(ctx context.Context, domain string) (*Tenant, error) {
	var t Tenant
	var configJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, config, created_at, updated_at
		FROM tenants WHERE domain = $1
	`, domain).Scan(&t.ID, &t.Name, &t.Domain, &t.Plan, &configJSON, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("tenant not found for domain: %w", err)
	}

	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &t.Config); err != nil {
			s.logger.Warn("Failed to unmarshal tenant config", zap.Error(err))
			t.Config = DefaultTenantConfig()
		}
	} else {
		t.Config = DefaultTenantConfig()
	}

	return &t, nil
}

// CreateTenant creates a new tenant
func (s *Service) CreateTenant(ctx context.Context, req CreateTenantRequest) (*Tenant, error) {
	// Check if domain already exists
	var exists bool
	err := s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tenants WHERE domain = $1)", req.Domain).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("failed to check domain existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("domain already exists")
	}

	// Use default config if not provided
	config := req.Config
	if config.Branding.PrimaryColor == "" {
		config = DefaultTenantConfig()
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	id := uuid.New().String()
	now := time.Now()

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO tenants (id, name, domain, plan, config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, id, req.Name, req.Domain, req.Plan, configJSON, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	return &Tenant{
		ID:        id,
		Name:      req.Name,
		Domain:    req.Domain,
		Plan:      req.Plan,
		Config:    config,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// UpdateTenant updates an existing tenant
func (s *Service) UpdateTenant(ctx context.Context, id string, req UpdateTenantRequest) (*Tenant, error) {
	// Get existing tenant
	existing, err := s.GetTenant(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Domain != nil {
		// Check if new domain already exists
		var exists bool
		err := s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tenants WHERE domain = $1 AND id != $2)", *req.Domain, id).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("failed to check domain existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("domain already exists")
		}
		existing.Domain = *req.Domain
	}
	if req.Plan != nil {
		existing.Plan = *req.Plan
	}
	if req.Config != nil {
		existing.Config = *req.Config
	}

	configJSON, err := json.Marshal(existing.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	existing.UpdatedAt = time.Now()

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE tenants
		SET name = $1, domain = $2, plan = $3, config = $4, updated_at = $5
		WHERE id = $6
	`, existing.Name, existing.Domain, existing.Plan, configJSON, existing.UpdatedAt, id)
	if err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	return existing, nil
}

// DeleteTenant deletes a tenant
func (s *Service) DeleteTenant(ctx context.Context, id string) error {
	result, err := s.db.Pool.Exec(ctx, "DELETE FROM tenants WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found")
	}
	return nil
}

// DefaultTenantConfig returns default tenant configuration
func DefaultTenantConfig() TenantConfig {
	return TenantConfig{
		Branding: TenantBranding{
			PrimaryColor:   "#0066cc",
			SecondaryColor: "#6c757d",
			LoginTitle:     "Sign In",
		},
		Security: TenantSecurity{},
		Features: TenantFeatures{
			SCIMProvisioning: false,
			SAMLSSO:          false,
			APIAccess:        true,
			AuditLogRetention: 90,
		},
		Limits: TenantLimits{
			MaxUsers:   1000,
			MaxGroups:  100,
			MaxApps:    50,
			MaxAdmins:  10,
			MaxAPIKeys: 20,
		},
		PasswordPolicy: PasswordPolicy{
			MinLength:        12,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSpecial:   true,
			MaxAge:           90,
			History:          5,
		},
		SessionPolicy: SessionPolicy{
			TimeoutMinutes: 60,
			MaxConcurrent:  5,
		},
		MFAPolicy: TenantMFAPolicy{
			RequiredForRoles: []string{"admin"},
			AllowedMethods:   []string{"totp", "sms"},
		},
		RateLimit: RateLimitConfig{
			PerIP:   100,
			PerUser: 50,
		},
	}
}

// TenantIsolationMiddleware injects tenant_id into context for all queries
func (s *Service) TenantIsolationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant from domain header or JWT claim
		tenantID := ""

		// Try from header first
		if domain := c.GetHeader("X-Tenant-Domain"); domain != "" {
			tenant, err := s.GetTenantByDomain(c.Request.Context(), domain)
			if err == nil {
				tenantID = tenant.ID
			}
		}

		// Fall back to JWT claim
		if tenantID == "" {
			if tid, exists := c.Get("tenant_id"); exists {
				if tidStr, ok := tid.(string); ok {
					tenantID = tidStr
				}
			}
		}

		// Use default tenant if still not set
		if tenantID == "" {
			tenantID = "00000000-0000-0000-0000-000000000010"
		}

		c.Set("tenant_id", tenantID)
		c.Next()
	}
}

// --- Handlers ---

// handleListTenants handles GET /api/v1/admin/tenants
func (s *Service) handleListTenants(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := parseIntParam(p, 1, 1000); err == nil {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := parseIntParam(ps, 1, 100); err == nil {
			pageSize = parsed
		}
	}

	resp, err := s.ListTenants(c.Request.Context(), page, pageSize)
	if err != nil {
		s.logger.Error("Failed to list tenants", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleGetTenant handles GET /api/v1/admin/tenants/:id
func (s *Service) handleGetTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tenant, err := s.GetTenant(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// handleCreateTenant handles POST /api/v1/admin/tenants
func (s *Service) handleCreateTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant, err := s.CreateTenant(c.Request.Context(), req)
	if err != nil {
		s.logger.Error("Failed to create tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, tenant)
}

// handleUpdateTenant handles PUT /api/v1/admin/tenants/:id
func (s *Service) handleUpdateTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant, err := s.UpdateTenant(c.Request.Context(), id, req)
	if err != nil {
		s.logger.Error("Failed to update tenant", zap.Error(err))
		if err.Error() == "tenant not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// handleDeleteTenant handles DELETE /api/v1/admin/tenants/:id
func (s *Service) handleDeleteTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	err := s.DeleteTenant(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("Failed to delete tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted successfully"})
}

func parseIntParam(s string, min, max int) (int, error) {
	var val int
	if _, err := fmt.Sscanf(s, "%d", &val); err != nil {
		return 0, fmt.Errorf("invalid integer")
	}
	if val < min {
		val = min
	}
	if val > max {
		val = max
	}
	return val, nil
}
