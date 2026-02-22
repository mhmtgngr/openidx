package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// TenantBranding represents organization-level tenant branding configuration
type TenantBranding struct {
	ID                 string          `json:"id"`
	OrgID              string          `json:"org_id"`
	LogoURL            string          `json:"logo_url"`
	FaviconURL         string          `json:"favicon_url"`
	PrimaryColor       string          `json:"primary_color"`
	SecondaryColor     string          `json:"secondary_color"`
	BackgroundColor    string          `json:"background_color"`
	BackgroundImageURL string          `json:"background_image_url"`
	LoginPageTitle     string          `json:"login_page_title"`
	LoginPageMessage   string          `json:"login_page_message"`
	PortalTitle        string          `json:"portal_title"`
	CustomCSS          string          `json:"custom_css"`
	CustomFooter       string          `json:"custom_footer"`
	PoweredByVisible   bool            `json:"powered_by_visible"`
	Metadata           json.RawMessage `json:"metadata"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// TenantSetting represents a category of tenant settings
type TenantSetting struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	Category  string          `json:"category"`
	Settings  json.RawMessage `json:"settings"`
	UpdatedBy *string         `json:"updated_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// TenantDomain represents a custom domain registered for a tenant
type TenantDomain struct {
	ID                string     `json:"id"`
	OrgID             string     `json:"org_id"`
	Domain            string     `json:"domain"`
	DomainType        string     `json:"domain_type"`
	Verified          bool       `json:"verified"`
	VerificationToken string     `json:"verification_token,omitempty"`
	VerifiedAt        *time.Time `json:"verified_at"`
	SSLEnabled        bool       `json:"ssl_enabled"`
	PrimaryDomain     bool       `json:"primary_domain"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// handleGetTenantBranding retrieves the branding configuration for a tenant organization
func (s *Service) handleGetTenantBranding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")

	var b TenantBranding
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, org_id, logo_url, favicon_url, primary_color, secondary_color,
		        background_color, background_image_url, login_page_title, login_page_message,
		        portal_title, custom_css, custom_footer, powered_by_visible, metadata,
		        created_at, updated_at
		 FROM tenant_branding WHERE org_id = $1`, orgID,
	).Scan(&b.ID, &b.OrgID, &b.LogoURL, &b.FaviconURL, &b.PrimaryColor, &b.SecondaryColor,
		&b.BackgroundColor, &b.BackgroundImageURL, &b.LoginPageTitle, &b.LoginPageMessage,
		&b.PortalTitle, &b.CustomCSS, &b.CustomFooter, &b.PoweredByVisible, &b.Metadata,
		&b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		// Return defaults if no branding exists
		c.JSON(http.StatusOK, TenantBranding{
			OrgID:            orgID,
			PrimaryColor:     "#1e40af",
			SecondaryColor:   "#3b82f6",
			BackgroundColor:  "#ffffff",
			LoginPageTitle:   "Sign In",
			LoginPageMessage: "Welcome to OpenIDX",
			PortalTitle:      "OpenIDX Portal",
			CustomFooter:     "Powered by OpenIDX - Open Source Zero Trust Access Platform",
			PoweredByVisible: true,
		})
		return
	}
	c.JSON(http.StatusOK, b)
}

// handleUpdateTenantBranding upserts the branding configuration for a tenant organization
func (s *Service) handleUpdateTenantBranding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")

	var req struct {
		LogoURL            string          `json:"logo_url"`
		FaviconURL         string          `json:"favicon_url"`
		PrimaryColor       string          `json:"primary_color"`
		SecondaryColor     string          `json:"secondary_color"`
		BackgroundColor    string          `json:"background_color"`
		BackgroundImageURL string          `json:"background_image_url"`
		LoginPageTitle     string          `json:"login_page_title"`
		LoginPageMessage   string          `json:"login_page_message"`
		PortalTitle        string          `json:"portal_title"`
		CustomCSS          string          `json:"custom_css"`
		CustomFooter       string          `json:"custom_footer"`
		PoweredByVisible   bool            `json:"powered_by_visible"`
		Metadata           json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO tenant_branding (org_id, logo_url, favicon_url, primary_color, secondary_color,
		    background_color, background_image_url, login_page_title, login_page_message,
		    portal_title, custom_css, custom_footer, powered_by_visible, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (org_id) DO UPDATE SET
		    logo_url = EXCLUDED.logo_url, favicon_url = EXCLUDED.favicon_url,
		    primary_color = EXCLUDED.primary_color, secondary_color = EXCLUDED.secondary_color,
		    background_color = EXCLUDED.background_color, background_image_url = EXCLUDED.background_image_url,
		    login_page_title = EXCLUDED.login_page_title, login_page_message = EXCLUDED.login_page_message,
		    portal_title = EXCLUDED.portal_title, custom_css = EXCLUDED.custom_css,
		    custom_footer = EXCLUDED.custom_footer, powered_by_visible = EXCLUDED.powered_by_visible,
		    metadata = EXCLUDED.metadata, updated_at = NOW()`,
		orgID, req.LogoURL, req.FaviconURL, req.PrimaryColor, req.SecondaryColor,
		req.BackgroundColor, req.BackgroundImageURL, req.LoginPageTitle, req.LoginPageMessage,
		req.PortalTitle, req.CustomCSS, req.CustomFooter, req.PoweredByVisible, req.Metadata)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update branding", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Branding updated"})
}

// handleGetTenantSettings retrieves tenant settings, optionally filtered by category
func (s *Service) handleGetTenantSettings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	category := c.Query("category")

	if category != "" {
		var ts TenantSetting
		err := s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT id, org_id, category, settings, updated_by, created_at, updated_at
			 FROM tenant_settings WHERE org_id = $1 AND category = $2`, orgID, category,
		).Scan(&ts.ID, &ts.OrgID, &ts.Category, &ts.Settings, &ts.UpdatedBy, &ts.CreatedAt, &ts.UpdatedAt)
		if err != nil {
			respondError(c, nil, apperrors.NotFound("Settings"))
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": []TenantSetting{ts}})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, org_id, category, settings, updated_by, created_at, updated_at
		 FROM tenant_settings WHERE org_id = $1 ORDER BY category`, orgID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list settings", err))
		return
	}
	defer rows.Close()

	var settings []TenantSetting
	for rows.Next() {
		var ts TenantSetting
		if err := rows.Scan(&ts.ID, &ts.OrgID, &ts.Category, &ts.Settings, &ts.UpdatedBy, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
			continue
		}
		settings = append(settings, ts)
	}
	if settings == nil {
		settings = []TenantSetting{}
	}
	c.JSON(http.StatusOK, gin.H{"data": settings})
}

// handleUpdateTenantSettings upserts tenant settings for a given category
func (s *Service) handleUpdateTenantSettings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")

	var req struct {
		Category string          `json:"category"`
		Settings json.RawMessage `json:"settings"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var updatedBy *string
	if userIDStr != "" {
		updatedBy = &userIDStr
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO tenant_settings (org_id, category, settings, updated_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id, category) DO UPDATE SET
		    settings = EXCLUDED.settings, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		orgID, req.Category, req.Settings, updatedBy)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update settings", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated"})
}

// handleListTenantDomains lists all custom domains for a tenant organization
func (s *Service) handleListTenantDomains(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, org_id, domain, domain_type, verified, verification_token, verified_at,
		        ssl_enabled, primary_domain, created_at, updated_at
		 FROM tenant_domains WHERE org_id = $1 ORDER BY primary_domain DESC, created_at`, orgID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list domains", err))
		return
	}
	defer rows.Close()

	var domains []TenantDomain
	for rows.Next() {
		var d TenantDomain
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Domain, &d.DomainType, &d.Verified,
			&d.VerificationToken, &d.VerifiedAt, &d.SSLEnabled, &d.PrimaryDomain,
			&d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		domains = append(domains, d)
	}
	if domains == nil {
		domains = []TenantDomain{}
	}
	c.JSON(http.StatusOK, gin.H{"data": domains})
}

// handleCreateTenantDomain registers a new custom domain for a tenant organization
func (s *Service) handleCreateTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")

	var req struct {
		Domain     string `json:"domain"`
		DomainType string `json:"domain_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	// Generate a verification token (16 random bytes, hex-encoded)
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to generate verification token", err))
		return
	}
	verificationToken := hex.EncodeToString(tokenBytes)

	var d TenantDomain
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO tenant_domains (org_id, domain, domain_type, verification_token)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, domain, domain_type, verified, verification_token, verified_at,
		           ssl_enabled, primary_domain, created_at, updated_at`,
		orgID, req.Domain, req.DomainType, verificationToken,
	).Scan(&d.ID, &d.OrgID, &d.Domain, &d.DomainType, &d.Verified,
		&d.VerificationToken, &d.VerifiedAt, &d.SSLEnabled, &d.PrimaryDomain,
		&d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create domain", err))
		return
	}

	c.JSON(http.StatusCreated, d)
}

// handleDeleteTenantDomain removes a custom domain from a tenant organization
func (s *Service) handleDeleteTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	domainID := c.Param("domainId")

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM tenant_domains WHERE id = $1 AND org_id = $2`, domainID, orgID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete domain", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Domain"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain deleted"})
}

// handleVerifyTenantDomain verifies a custom domain using the verification token
func (s *Service) handleVerifyTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	domainID := c.Param("domainId")

	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	var storedToken string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT verification_token FROM tenant_domains WHERE id = $1 AND org_id = $2`,
		domainID, orgID,
	).Scan(&storedToken)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Domain"))
		return
	}

	if storedToken != req.Token {
		respondError(c, nil, apperrors.BadRequest("Verification token does not match"))
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE tenant_domains SET verified = true, verified_at = NOW(), updated_at = NOW()
		 WHERE id = $1 AND org_id = $2`, domainID, orgID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to verify domain", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain verified"})
}

// handleSwitchTenant switches the current tenant context to a different organization
func (s *Service) handleSwitchTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		OrgID string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	var org struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		DisplayName string  `json:"display_name"`
		Domain      *string `json:"domain"`
		Enabled     bool    `json:"enabled"`
	}
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, display_name, domain, enabled
		 FROM organizations WHERE id = $1`, req.OrgID,
	).Scan(&org.ID, &org.Name, &org.DisplayName, &org.Domain, &org.Enabled)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Organization"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Tenant switched",
		"organization": org,
	})
}

// handleGetCurrentTenant retrieves the current tenant organization for the authenticated user
func (s *Service) handleGetCurrentTenant(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	if userIDStr == "" {
		respondError(c, nil, apperrors.BadRequest("User ID not found in context"))
		return
	}

	var org struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		DisplayName string  `json:"display_name"`
		Domain      *string `json:"domain"`
		Enabled     bool    `json:"enabled"`
	}
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT o.id, o.name, o.display_name, o.domain, o.enabled
		 FROM organizations o
		 JOIN organization_members om ON o.id = om.organization_id
		 WHERE om.user_id = $1
		 LIMIT 1`, userIDStr,
	).Scan(&org.ID, &org.Name, &org.DisplayName, &org.Domain, &org.Enabled)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Organization"))
		return
	}

	// Also fetch branding for the organization
	var branding TenantBranding
	brandingErr := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, org_id, logo_url, favicon_url, primary_color, secondary_color,
		        background_color, background_image_url, login_page_title, login_page_message,
		        portal_title, custom_css, custom_footer, powered_by_visible, metadata,
		        created_at, updated_at
		 FROM tenant_branding WHERE org_id = $1`, org.ID,
	).Scan(&branding.ID, &branding.OrgID, &branding.LogoURL, &branding.FaviconURL,
		&branding.PrimaryColor, &branding.SecondaryColor, &branding.BackgroundColor,
		&branding.BackgroundImageURL, &branding.LoginPageTitle, &branding.LoginPageMessage,
		&branding.PortalTitle, &branding.CustomCSS, &branding.CustomFooter,
		&branding.PoweredByVisible, &branding.Metadata, &branding.CreatedAt, &branding.UpdatedAt)
	if brandingErr != nil {
		// Use defaults if no branding exists
		branding = TenantBranding{
			OrgID:            org.ID,
			PrimaryColor:     "#1e40af",
			SecondaryColor:   "#3b82f6",
			BackgroundColor:  "#ffffff",
			LoginPageTitle:   "Sign In",
			LoginPageMessage: "Welcome to OpenIDX",
			PortalTitle:      "OpenIDX Portal",
			CustomFooter:     "Powered by OpenIDX - Open Source Zero Trust Access Platform",
			PoweredByVisible: true,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"organization": org,
		"branding":     branding,
	})
}
