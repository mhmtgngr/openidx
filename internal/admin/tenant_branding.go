package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TenantBrandingRecord represents organization-level tenant branding configuration in the database
type TenantBrandingRecord struct {
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

	// VerificationRecord is the DNS record whose presence verifies the domain,
	// set while it is unverified.
	VerificationRecord *DomainVerificationRecord `json:"verification_record,omitempty"`
}

// DomainVerificationRecord is the TXT record an organization publishes to prove
// it controls a domain it has claimed.
type DomainVerificationRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// A domain is verified by DNS, never on an administrator's word: the record
// named domainChallengeLabel under the domain must hold domainChallengePrefix
// followed by the token its claim was given. Only whoever runs the domain's DNS
// can publish that, and the token is the claim's own, so one organization's
// record verifies no other organization's claim. The label keeps the record
// off the host itself, which is usually a CNAME to the install and can carry
// no other record.
const (
	domainChallengeLabel  = "_openidx-challenge"
	domainChallengePrefix = "openidx-domain-verification="

	// domainLookupTimeout bounds the lookup the verify request waits on.
	domainLookupTimeout = 5 * time.Second
)

// TXTResolver looks up the TXT records at a name. *net.Resolver satisfies it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// SetTXTResolver replaces the resolver domain verification looks records up
// with; nil restores net.DefaultResolver.
func (s *Service) SetTXTResolver(r TXTResolver) {
	s.txtResolver = r
}

func (s *Service) domainResolver() TXTResolver {
	if s.txtResolver != nil {
		return s.txtResolver
	}
	return net.DefaultResolver
}

// domainVerificationRecord is the record that verifies a claim to domain with
// token.
func domainVerificationRecord(domain, token string) *DomainVerificationRecord {
	return &DomainVerificationRecord{
		Type:  "TXT",
		Name:  domainChallengeLabel + "." + domain,
		Value: domainChallengePrefix + token,
	}
}

// normalizeDomain returns the host name a claim is stored under: lower case,
// without a trailing dot, and a DNS name of letters, digits and hyphens with at
// least two labels, short enough that its challenge name is one too. Browsers
// report the login page's host this way, and the branding lookup compares it
// exactly.
func normalizeDomain(raw string) (string, bool) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if d == "" || len(domainChallengeLabel)+1+len(d) > 253 {
		return "", false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", false
			}
		}
	}
	// A name whose last label is numeric is an IPv4 address, not a domain.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false
	}
	return d, true
}

// tenantOrgAllowed holds a /tenants/:orgId route to the organization the
// request resolved to. tenant_branding, tenant_settings and tenant_domains span
// the install, outside the RLS belt -- the login page reads branding by slug or
// domain before any organization is resolved -- so the id in the path was all
// that scoped these handlers, and an administrator of one organization could
// read and rewrite another's login-page branding and settings and add, verify
// and delete its custom domains. A platform admin may still name any
// organization; anyone else is answered 404 for any organization but their
// own, as for one that does not exist.
func tenantOrgAllowed(c *gin.Context, orgID string) bool {
	ctx := c.Request.Context()
	if orgctx.IsPlatformAdmin(ctx) {
		return true
	}
	if org, err := orgctx.From(ctx); err == nil && org.ID == orgID {
		return true
	}
	respondError(c, nil, apperrors.NotFound("Organization"))
	return false
}

// handleGetTenantBrandingRecord retrieves the branding configuration for a tenant organization
func (s *Service) handleGetTenantBrandingRecord(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	if !tenantOrgAllowed(c, orgID) {
		return
	}

	var b TenantBrandingRecord
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
		c.JSON(http.StatusOK, TenantBrandingRecord{
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

// handleUpdateTenantBrandingRecord upserts the branding configuration for a tenant organization
func (s *Service) handleUpdateTenantBrandingRecord(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	if !tenantOrgAllowed(c, orgID) {
		return
	}

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
	if !tenantOrgAllowed(c, orgID) {
		return
	}
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
	if !tenantOrgAllowed(c, orgID) {
		return
	}

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
	if !tenantOrgAllowed(c, orgID) {
		return
	}

	// A row written by hand may carry no token; scanning its NULL into a string
	// used to fail, and the row was skipped, so a verified domain could be
	// missing from its organization's own list.
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, org_id, domain, domain_type, verified, COALESCE(verification_token, ''), verified_at,
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
		if !d.Verified && d.VerificationToken != "" {
			d.VerificationRecord = domainVerificationRecord(d.Domain, d.VerificationToken)
		}
		domains = append(domains, d)
	}
	if domains == nil {
		domains = []TenantDomain{}
	}
	c.JSON(http.StatusOK, gin.H{"data": domains})
}

// handleCreateTenantDomain registers a new custom domain for a tenant
// organization. The claim is unverified and carries the TXT record that will
// verify it.
//
// An unverified claim holds nothing, so it does not keep another organization
// from claiming the same domain: the one that proves control in DNS gets it,
// and a squatter's claim cannot stand in the real owner's way. A domain another
// organization has already verified is refused with 409, which tells the
// caller that the domain is taken on this install and nothing about by whom.
func (s *Service) handleCreateTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	if !tenantOrgAllowed(c, orgID) {
		return
	}

	var req struct {
		Domain     string `json:"domain"`
		DomainType string `json:"domain_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}
	domain, ok := normalizeDomain(req.Domain)
	if !ok {
		respondError(c, nil, apperrors.BadRequest("domain must be a DNS name such as login.example.com"))
		return
	}
	switch req.DomainType {
	case "":
		req.DomainType = "subdomain"
	case "subdomain", "custom":
	default:
		respondError(c, nil, apperrors.BadRequest("domain_type must be subdomain or custom"))
		return
	}

	ctx := c.Request.Context()
	var verifiedElsewhere bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenant_domains WHERE domain = $1 AND verified AND org_id <> $2)`,
		domain, orgID).Scan(&verifiedElsewhere); err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create domain", err))
		return
	}
	if verifiedElsewhere {
		respondError(c, nil, apperrors.Conflict("Another organization has verified this domain"))
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
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO tenant_domains (org_id, domain, domain_type, verification_token)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, domain, domain_type, verified, verification_token, verified_at,
		           ssl_enabled, primary_domain, created_at, updated_at`,
		orgID, domain, req.DomainType, verificationToken,
	).Scan(&d.ID, &d.OrgID, &d.Domain, &d.DomainType, &d.Verified,
		&d.VerificationToken, &d.VerifiedAt, &d.SSLEnabled, &d.PrimaryDomain,
		&d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			respondError(c, nil, apperrors.Conflict("This organization has already added this domain"))
			return
		}
		respondError(c, s.logger, apperrors.Internal("Failed to create domain", err))
		return
	}
	d.VerificationRecord = domainVerificationRecord(d.Domain, d.VerificationToken)

	c.JSON(http.StatusCreated, d)
}

// handleDeleteTenantDomain removes a custom domain from a tenant organization
func (s *Service) handleDeleteTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	if !tenantOrgAllowed(c, orgID) {
		return
	}
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

// handleVerifyTenantDomain verifies a claimed domain by looking up its TXT
// record. The request body is not read: nothing the caller sends can stand in
// for the record.
//
// It used to compare a token in the request with the one the domain list had
// just shown the same administrator, so an administrator of any organization
// could mark any host verified -- the install's own login host included, where
// the public branding endpoint would then serve their logo, texts and custom
// CSS on the page every organization's users sign in at.
func (s *Service) handleVerifyTenantDomain(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	orgID := c.Param("orgId")
	if !tenantOrgAllowed(c, orgID) {
		return
	}
	domainID := c.Param("domainId")
	ctx := c.Request.Context()

	var domain, token string
	var verified bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT domain, COALESCE(verification_token, ''), verified FROM tenant_domains WHERE id = $1 AND org_id = $2`,
		domainID, orgID,
	).Scan(&domain, &token, &verified)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Domain"))
		return
	}
	if verified {
		c.JSON(http.StatusOK, gin.H{"message": "Domain verified"})
		return
	}
	// With no token, the expected value would be the bare prefix, which anyone
	// could publish on a domain whose claim was written by hand.
	if token == "" {
		respondError(c, nil, apperrors.BadRequest("This domain has no verification token; remove it and add it again"))
		return
	}

	var verifiedElsewhere bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenant_domains WHERE domain = $1 AND verified AND org_id <> $2)`,
		domain, orgID).Scan(&verifiedElsewhere); err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to verify domain", err))
		return
	}
	if verifiedElsewhere {
		respondError(c, nil, apperrors.Conflict("Another organization has verified this domain"))
		return
	}

	record := domainVerificationRecord(domain, token)
	lookupCtx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
	values, err := s.domainResolver().LookupTXT(lookupCtx, record.Name)
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			s.logger.Warn("tenant domain verification: DNS lookup failed",
				logsafe.String("name", record.Name), zap.Error(err))
			respondError(c, nil, apperrors.New("DNS_LOOKUP_FAILED",
				"The DNS lookup of "+record.Name+" failed; try again", http.StatusBadGateway))
			return
		}
		values = nil
	}
	found := false
	for _, v := range values {
		if v == record.Value {
			found = true
			break
		}
	}
	if !found {
		respondError(c, nil, apperrors.BadRequest(
			"No TXT record at "+record.Name+" holds "+record.Value+"; publish it and try again"))
		return
	}

	// Mark this claim verified and drop every other organization's unverified
	// claim to the domain, together: after this the domain is this
	// organization's until it removes it. The partial unique index on verified
	// domains settles a race with another organization verifying the same
	// domain -- whose record would have had to be published too.
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to verify domain", err))
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE tenant_domains SET verified = true, verified_at = NOW(), updated_at = NOW()
		 WHERE id = $1 AND org_id = $2 AND NOT verified`, domainID, orgID)
	if err != nil {
		if isUniqueViolation(err) {
			respondError(c, nil, apperrors.Conflict("Another organization has verified this domain"))
			return
		}
		respondError(c, s.logger, apperrors.Internal("Failed to verify domain", err))
		return
	}
	if tag.RowsAffected() == 0 {
		// Deleted, or verified by a concurrent request, since it was read.
		respondError(c, nil, apperrors.NotFound("Domain"))
		return
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM tenant_domains WHERE domain = $1 AND org_id <> $2 AND NOT verified`,
		domain, orgID); err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to verify domain", err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		if isUniqueViolation(err) {
			respondError(c, nil, apperrors.Conflict("Another organization has verified this domain"))
			return
		}
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
	// The organization switched to is the caller's own, one they are a member
	// of, or -- for a platform admin -- any. organizations is outside the RLS
	// belt, so without this any administrator read any organization's name and
	// domain by its id; anyone else is answered 404, as for an unknown id.
	if !s.maySwitchTo(c, req.OrgID) {
		respondError(c, nil, apperrors.NotFound("Organization"))
		return
	}

	var org struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		DisplayName string  `json:"display_name"`
		Domain      *string `json:"domain"`
		Enabled     bool    `json:"enabled"`
	}
	// organizations is (id, name, slug, domain, plan, status, ...). It has
	// neither display_name nor enabled, so this SELECT could never plan and
	// every switch answered 404 "Organization not found" -- the console's
	// tenant switcher has never worked. name doubles as the display name, and
	// status = 'active' is what enabled meant.
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, name, domain, status = 'active'
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

// maySwitchTo reports whether the caller may switch to orgID: a platform admin
// always, anyone else to the organization the request resolved to or one
// organization_members lists them in. A lookup that fails answers no.
func (s *Service) maySwitchTo(c *gin.Context, orgID string) bool {
	ctx := c.Request.Context()
	if orgctx.IsPlatformAdmin(ctx) {
		return true
	}
	if org, err := orgctx.From(ctx); err == nil && org.ID == orgID {
		return true
	}
	userID := c.GetString("user_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return false
	}
	if _, err := uuid.Parse(userID); err != nil {
		return false
	}
	var member bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM organization_members WHERE organization_id = $1 AND user_id = $2)`,
		orgID, userID).Scan(&member); err != nil {
		s.logger.Warn("tenant switch: membership lookup failed; refusing", zap.Error(err))
		return false
	}
	return member
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
	// Same two absent columns as handleSwitchTenant: this is the lookup of
	// the caller's current organization, and it answered 404 every time.
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT o.id, o.name, o.name, o.domain, o.status = 'active'
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
	var branding TenantBrandingRecord
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
		branding = TenantBrandingRecord{
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
