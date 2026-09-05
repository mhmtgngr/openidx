package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// isUniqueViolation reports whether err is a Postgres 23505 unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// SocialProvider represents a social/external identity provider configuration
type SocialProvider struct {
	ID               string          `json:"id"`
	ProviderID       string          `json:"provider_id"`
	ProviderKey      string          `json:"provider_key"` // google, github, microsoft, apple
	DisplayName      string          `json:"display_name"`
	IconURL          string          `json:"icon_url"`
	ButtonColor      string          `json:"button_color"`
	ButtonText       string          `json:"button_text"`
	AutoCreateUsers  bool            `json:"auto_create_users"`
	AutoLinkByEmail  bool            `json:"auto_link_by_email"`
	DefaultRole      string          `json:"default_role"`
	AllowedDomains   json.RawMessage `json:"allowed_domains"`
	AttributeMapping json.RawMessage `json:"attribute_mapping"`
	Enabled          bool            `json:"enabled"`
	SortOrder        int             `json:"sort_order"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// FederationRule represents a domain-to-provider routing rule
type FederationRule struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	EmailDomain  string          `json:"email_domain"`
	ProviderID   string          `json:"provider_id"`
	ProviderName string          `json:"provider_name,omitempty"` // from JOIN
	Priority     int             `json:"priority"`
	AutoRedirect bool            `json:"auto_redirect"`
	Enabled      bool            `json:"enabled"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// UserIdentityLink represents a link between a local user and an external identity
type UserIdentityLink struct {
	ID               string          `json:"id"`
	UserID           string          `json:"user_id"`
	ProviderID       string          `json:"provider_id"`
	ProviderName     string          `json:"provider_name,omitempty"` // from JOIN
	ExternalID       string          `json:"external_id"`
	ExternalEmail    *string         `json:"external_email"`
	ExternalUsername *string         `json:"external_username"`
	DisplayName      *string         `json:"display_name"`
	ProfileData      json.RawMessage `json:"profile_data"`
	IsPrimary        bool            `json:"is_primary"`
	LinkedAt         time.Time       `json:"linked_at"`
	LastUsedAt       *time.Time      `json:"last_used_at"`
}

// CustomClaimMapping represents a custom claim mapping for an application
type CustomClaimMapping struct {
	ID                   string          `json:"id"`
	ApplicationID        string          `json:"application_id"`
	ClaimName            string          `json:"claim_name"`
	SourceType           string          `json:"source_type"` // user_attribute, group_membership, static_value, expression
	SourceValue          string          `json:"source_value"`
	ClaimType            string          `json:"claim_type"` // string, number, boolean, array
	IncludeInIDToken     bool            `json:"include_in_id_token"`
	IncludeInAccessToken bool            `json:"include_in_access_token"`
	IncludeInUserinfo    bool            `json:"include_in_userinfo"`
	Condition            json.RawMessage `json:"condition"`
	Enabled              bool            `json:"enabled"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

// --- Social Providers ---

func (s *Service) handleListSocialProviders(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// The org predicate has to be in the WHERE clause. It used to sit only in
	// the LEFT JOIN's ON, which decides whether the joined identity_providers
	// row contributes and filters NOTHING on social_providers -- so this listed
	// every tenant's sign-in providers to every tenant, with the org check
	// blanking out nothing but the idp_name column of the ones that belonged to
	// somebody else. It is kept in the ON clause too: a provider must not be
	// labelled with an identity provider from another org.
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT sp.id, COALESCE(sp.provider_id::text, ''), sp.provider_key, sp.display_name, sp.icon_url,
		        sp.button_color, sp.button_text, sp.auto_create_users, sp.auto_link_by_email,
		        sp.default_role, sp.allowed_domains, sp.attribute_mapping, sp.enabled,
		        sp.sort_order, sp.created_at, sp.updated_at,
		        COALESCE(ip.name, '') as idp_name
		 FROM social_providers sp
		 LEFT JOIN identity_providers ip ON sp.provider_id = ip.id AND ip.org_id = $1
		 WHERE sp.org_id = $1
		 ORDER BY sp.sort_order`, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list social providers", err))
		return
	}
	defer rows.Close()

	type socialProviderWithIDP struct {
		SocialProvider
		IDPName string `json:"idp_name"`
	}

	var providers []socialProviderWithIDP
	for rows.Next() {
		var p socialProviderWithIDP
		if err := rows.Scan(&p.ID, &p.ProviderID, &p.ProviderKey, &p.DisplayName, &p.IconURL,
			&p.ButtonColor, &p.ButtonText, &p.AutoCreateUsers, &p.AutoLinkByEmail,
			&p.DefaultRole, &p.AllowedDomains, &p.AttributeMapping, &p.Enabled,
			&p.SortOrder, &p.CreatedAt, &p.UpdatedAt, &p.IDPName); err != nil {
			continue
		}
		providers = append(providers, p)
	}
	if providers == nil {
		providers = []socialProviderWithIDP{}
	}
	c.JSON(http.StatusOK, gin.H{"data": providers})
}

func (s *Service) handleCreateSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		ProviderID       string          `json:"provider_id"`
		ProviderKey      string          `json:"provider_key"`
		DisplayName      string          `json:"display_name"`
		IconURL          string          `json:"icon_url"`
		ButtonColor      string          `json:"button_color"`
		ButtonText       string          `json:"button_text"`
		AutoCreateUsers  bool            `json:"auto_create_users"`
		AutoLinkByEmail  bool            `json:"auto_link_by_email"`
		DefaultRole      string          `json:"default_role"`
		AllowedDomains   json.RawMessage `json:"allowed_domains"`
		AttributeMapping json.RawMessage `json:"attribute_mapping"`
		Enabled          bool            `json:"enabled"`
		SortOrder        int             `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	// provider_id is an optional FK to identity_providers. The console's create
	// flow supplies only provider_key, so insert NULL when no UUID is given
	// (the column is nullable as of migration v127) rather than passing "" into
	// a uuid column, which 500'd with "invalid input syntax for type uuid".
	var providerIDArg interface{}
	if strings.TrimSpace(req.ProviderID) != "" {
		providerIDArg = req.ProviderID
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO social_providers (org_id, provider_id, provider_key, display_name, icon_url,
		  button_color, button_text, auto_create_users, auto_link_by_email,
		  default_role, allowed_domains, attribute_mapping, enabled, sort_order)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 RETURNING id`,
		org.ID, providerIDArg, req.ProviderKey, req.DisplayName, req.IconURL,
		req.ButtonColor, req.ButtonText, req.AutoCreateUsers, req.AutoLinkByEmail,
		req.DefaultRole, req.AllowedDomains, req.AttributeMapping, req.Enabled, req.SortOrder,
	).Scan(&id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create social provider", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Social provider created"})
}

func (s *Service) handleGetSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	var p SocialProvider
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, COALESCE(provider_id::text, ''), provider_key, display_name, icon_url,
		        button_color, button_text, auto_create_users, auto_link_by_email,
		        default_role, allowed_domains, attribute_mapping, enabled,
		        sort_order, created_at, updated_at
		 FROM social_providers WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&p.ID, &p.ProviderID, &p.ProviderKey, &p.DisplayName, &p.IconURL,
		&p.ButtonColor, &p.ButtonText, &p.AutoCreateUsers, &p.AutoLinkByEmail,
		&p.DefaultRole, &p.AllowedDomains, &p.AttributeMapping, &p.Enabled,
		&p.SortOrder, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("Social provider"))
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleUpdateSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		ProviderKey      *string          `json:"provider_key"`
		DisplayName      *string          `json:"display_name"`
		IconURL          *string          `json:"icon_url"`
		ButtonColor      *string          `json:"button_color"`
		ButtonText       *string          `json:"button_text"`
		AutoCreateUsers  *bool            `json:"auto_create_users"`
		AutoLinkByEmail  *bool            `json:"auto_link_by_email"`
		DefaultRole      *string          `json:"default_role"`
		AllowedDomains   *json.RawMessage `json:"allowed_domains"`
		AttributeMapping *json.RawMessage `json:"attribute_mapping"`
		Enabled          *bool            `json:"enabled"`
		SortOrder        *int             `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	// Build dynamic update
	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.ProviderKey != nil {
		sets = append(sets, fmt.Sprintf("provider_key = $%d", argIdx))
		args = append(args, *req.ProviderKey)
		argIdx++
	}
	if req.DisplayName != nil {
		sets = append(sets, fmt.Sprintf("display_name = $%d", argIdx))
		args = append(args, *req.DisplayName)
		argIdx++
	}
	if req.IconURL != nil {
		sets = append(sets, fmt.Sprintf("icon_url = $%d", argIdx))
		args = append(args, *req.IconURL)
		argIdx++
	}
	if req.ButtonColor != nil {
		sets = append(sets, fmt.Sprintf("button_color = $%d", argIdx))
		args = append(args, *req.ButtonColor)
		argIdx++
	}
	if req.ButtonText != nil {
		sets = append(sets, fmt.Sprintf("button_text = $%d", argIdx))
		args = append(args, *req.ButtonText)
		argIdx++
	}
	if req.AutoCreateUsers != nil {
		sets = append(sets, fmt.Sprintf("auto_create_users = $%d", argIdx))
		args = append(args, *req.AutoCreateUsers)
		argIdx++
	}
	if req.AutoLinkByEmail != nil {
		sets = append(sets, fmt.Sprintf("auto_link_by_email = $%d", argIdx))
		args = append(args, *req.AutoLinkByEmail)
		argIdx++
	}
	if req.DefaultRole != nil {
		sets = append(sets, fmt.Sprintf("default_role = $%d", argIdx))
		args = append(args, *req.DefaultRole)
		argIdx++
	}
	if req.AllowedDomains != nil {
		sets = append(sets, fmt.Sprintf("allowed_domains = $%d", argIdx))
		args = append(args, *req.AllowedDomains)
		argIdx++
	}
	if req.AttributeMapping != nil {
		sets = append(sets, fmt.Sprintf("attribute_mapping = $%d", argIdx))
		args = append(args, *req.AttributeMapping)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.SortOrder != nil {
		sets = append(sets, fmt.Sprintf("sort_order = $%d", argIdx))
		args = append(args, *req.SortOrder)
		argIdx++
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	args = append(args, id, org.ID)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	//
	// The org predicate makes the RowsAffected()==0 below mean "not yours or not
	// there" rather than only "not there": without it this edited another
	// tenant's sign-in button by id.
	query := fmt.Sprintf("UPDATE social_providers SET %s WHERE id = $%d AND org_id = $%d",
		joinStrings(sets, ", "), argIdx, argIdx+1)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update social provider", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Social provider"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Social provider updated"})
}

func (s *Service) handleDeleteSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM social_providers WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete social provider", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Social provider"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Social provider deleted"})
}

// --- Federation Rules ---

func (s *Service) handleListFederationRules(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// The LEFT JOIN below fetches a display name; it does NOT scope. A left
	// join keeps every row of the left table and nulls the right side, so
	// `ip.org_id = $1` sitting in its ON clause filtered nothing and this list
	// returned every organization's rules with an empty provider name on the
	// foreign ones. The login path's version of the same query is an inner
	// join, which is why that one was safe. The tenant term belongs in a WHERE
	// clause on the table being listed.
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT fr.id, fr.name, fr.email_domain, fr.provider_id,
		        COALESCE(ip.name, '') as provider_name,
		        fr.priority, fr.auto_redirect, fr.enabled, fr.metadata,
		        fr.created_at, fr.updated_at
		 FROM federation_rules fr
		 LEFT JOIN identity_providers ip ON fr.provider_id = ip.id AND ip.org_id = $1
		 WHERE fr.org_id = $1
		 ORDER BY fr.priority, fr.email_domain`, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list federation rules", err))
		return
	}
	defer rows.Close()

	var rules []FederationRule
	for rows.Next() {
		var r FederationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.EmailDomain, &r.ProviderID,
			&r.ProviderName, &r.Priority, &r.AutoRedirect, &r.Enabled, &r.Metadata,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []FederationRule{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rules})
}

func (s *Service) handleCreateFederationRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var req struct {
		Name         string          `json:"name"`
		EmailDomain  string          `json:"email_domain"`
		ProviderID   string          `json:"provider_id"`
		Priority     int             `json:"priority"`
		AutoRedirect bool            `json:"auto_redirect"`
		Enabled      bool            `json:"enabled"`
		Metadata     json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if !s.providerInOrg(c, req.ProviderID, org.ID) {
		respondError(c, nil, apperrors.BadRequest("Identity provider not found in this organization"))
		return
	}

	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO federation_rules (name, email_domain, provider_id, priority, auto_redirect, enabled, metadata, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id`,
		req.Name, req.EmailDomain, req.ProviderID, req.Priority, req.AutoRedirect, req.Enabled, req.Metadata, org.ID,
	).Scan(&id)
	if err != nil {
		// email_domain is unique per organization since v155. Say which case
		// this is: until then a second tenant registering a domain the first
		// already held got a bare 500 with no hint that the name was taken.
		if isUniqueViolation(err) {
			respondError(c, nil, apperrors.BadRequest(
				"A federation rule for this email domain already exists in this organization"))
			return
		}
		respondError(c, s.logger, apperrors.Internal("Failed to create federation rule", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Federation rule created"})
}

// providerInOrg reports whether an identity provider belongs to the caller's
// tenant. A federation rule names the provider that will authenticate a domain,
// so an unvalidated provider_id lets one organization point a rule at another's
// sign-in configuration.
func (s *Service) providerInOrg(c *gin.Context, providerID, orgID string) bool {
	if providerID == "" {
		return false
	}
	var one int
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT 1 FROM identity_providers WHERE id = $1 AND org_id = $2", providerID, orgID).Scan(&one)
	return err == nil
}

// applicationInOrg reports whether an application belongs to the caller's
// tenant. The custom-claims routes take the application id from the URL, so
// without this a tenant could attach claim mappings to an application it
// cannot even see.
func (s *Service) applicationInOrg(c *gin.Context, appID, orgID string) bool {
	if appID == "" {
		return false
	}
	var one int
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT 1 FROM applications WHERE id = $1 AND org_id = $2", appID, orgID).Scan(&one)
	return err == nil
}

func (s *Service) handleUpdateFederationRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	id := c.Param("id")
	var req struct {
		Name         *string          `json:"name"`
		EmailDomain  *string          `json:"email_domain"`
		ProviderID   *string          `json:"provider_id"`
		Priority     *int             `json:"priority"`
		AutoRedirect *bool            `json:"auto_redirect"`
		Enabled      *bool            `json:"enabled"`
		Metadata     *json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	// Re-pointing a rule at another organization's provider is the same defect
	// as creating one that way.
	if req.ProviderID != nil && !s.providerInOrg(c, *req.ProviderID, org.ID) {
		respondError(c, nil, apperrors.BadRequest("Identity provider not found in this organization"))
		return
	}

	// Build dynamic update
	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.EmailDomain != nil {
		sets = append(sets, fmt.Sprintf("email_domain = $%d", argIdx))
		args = append(args, *req.EmailDomain)
		argIdx++
	}
	if req.ProviderID != nil {
		sets = append(sets, fmt.Sprintf("provider_id = $%d", argIdx))
		args = append(args, *req.ProviderID)
		argIdx++
	}
	if req.Priority != nil {
		sets = append(sets, fmt.Sprintf("priority = $%d", argIdx))
		args = append(args, *req.Priority)
		argIdx++
	}
	if req.AutoRedirect != nil {
		sets = append(sets, fmt.Sprintf("auto_redirect = $%d", argIdx))
		args = append(args, *req.AutoRedirect)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Metadata != nil {
		sets = append(sets, fmt.Sprintf("metadata = $%d", argIdx))
		args = append(args, *req.Metadata)
		argIdx++
	}

	args = append(args, id, org.ID)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE federation_rules SET %s WHERE id = $%d AND org_id = $%d",
		joinStrings(sets, ", "), argIdx, argIdx+1)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update federation rule", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Federation rule"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Federation rule updated"})
}

func (s *Service) handleDeleteFederationRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Deleting another organization's rule is quiet: the domain simply stops
	// being federated and its users fall back to a password prompt.
	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM federation_rules WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete federation rule", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Federation rule"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Federation rule deleted"})
}

// --- User Identity Links ---

func (s *Service) handleListUserIdentityLinks(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	userID := c.Param("id")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT uil.id, uil.user_id, uil.provider_id,
		        COALESCE(ip.name, '') as provider_name,
		        uil.external_id, uil.external_email, uil.external_username,
		        uil.display_name, uil.profile_data, uil.is_primary,
		        uil.linked_at, uil.last_used_at
		 FROM user_identity_links uil
		 LEFT JOIN identity_providers ip ON uil.provider_id = ip.id AND ip.org_id = $2
		 WHERE uil.user_id = $1
		 ORDER BY uil.linked_at`, userID, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list identity links", err))
		return
	}
	defer rows.Close()

	var links []UserIdentityLink
	for rows.Next() {
		var l UserIdentityLink
		if err := rows.Scan(&l.ID, &l.UserID, &l.ProviderID,
			&l.ProviderName, &l.ExternalID, &l.ExternalEmail, &l.ExternalUsername,
			&l.DisplayName, &l.ProfileData, &l.IsPrimary,
			&l.LinkedAt, &l.LastUsedAt); err != nil {
			continue
		}
		links = append(links, l)
	}
	if links == nil {
		links = []UserIdentityLink{}
	}
	c.JSON(http.StatusOK, gin.H{"data": links})
}

func (s *Service) handleDeleteIdentityLink(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	linkID := c.Param("linkId")
	userID := c.Param("id")

	var tag interface{ RowsAffected() int64 }
	var err error

	if userID != "" {
		// Ensure the link belongs to the specified user (org_id safety check)
		tag, err = s.db.Pool.Exec(c.Request.Context(),
			"DELETE FROM user_identity_links WHERE id = $1 AND user_id = $2", linkID, userID)
	} else {
		tag, err = s.db.Pool.Exec(c.Request.Context(),
			"DELETE FROM user_identity_links WHERE id = $1", linkID)
	}
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete identity link", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Identity link"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Identity link deleted"})
}

// --- Custom Claims Mappings ---

func (s *Service) handleListCustomClaims(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	appID := c.Param("id")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, application_id, claim_name, source_type, source_value,
		        claim_type, include_in_id_token, include_in_access_token,
		        include_in_userinfo, condition, enabled, created_at, updated_at
		 FROM custom_claims_mappings WHERE application_id = $1 AND org_id = $2
		 ORDER BY claim_name`, appID, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list custom claims", err))
		return
	}
	defer rows.Close()

	var claims []CustomClaimMapping
	for rows.Next() {
		var cl CustomClaimMapping
		if err := rows.Scan(&cl.ID, &cl.ApplicationID, &cl.ClaimName, &cl.SourceType, &cl.SourceValue,
			&cl.ClaimType, &cl.IncludeInIDToken, &cl.IncludeInAccessToken,
			&cl.IncludeInUserinfo, &cl.Condition, &cl.Enabled, &cl.CreatedAt, &cl.UpdatedAt); err != nil {
			continue
		}
		claims = append(claims, cl)
	}
	if claims == nil {
		claims = []CustomClaimMapping{}
	}
	c.JSON(http.StatusOK, gin.H{"data": claims})
}

func (s *Service) handleCreateCustomClaim(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// A claim mapping decides what an application is told about the person
	// signing in, so attaching one to an application in another tenant is the
	// sharp end of this table -- currently blunted only by the fact that
	// nothing reads these rows (see the v155 header).
	appID := c.Param("id")
	if !s.applicationInOrg(c, appID, org.ID) {
		respondError(c, nil, apperrors.NotFound("Application"))
		return
	}

	var req struct {
		ClaimName            string          `json:"claim_name"`
		SourceType           string          `json:"source_type"`
		SourceValue          string          `json:"source_value"`
		ClaimType            string          `json:"claim_type"`
		IncludeInIDToken     bool            `json:"include_in_id_token"`
		IncludeInAccessToken bool            `json:"include_in_access_token"`
		IncludeInUserinfo    bool            `json:"include_in_userinfo"`
		Condition            json.RawMessage `json:"condition"`
		Enabled              bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO custom_claims_mappings (application_id, claim_name, source_type, source_value,
		  claim_type, include_in_id_token, include_in_access_token, include_in_userinfo, condition, enabled, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id`,
		appID, req.ClaimName, req.SourceType, req.SourceValue,
		req.ClaimType, req.IncludeInIDToken, req.IncludeInAccessToken,
		req.IncludeInUserinfo, req.Condition, req.Enabled, org.ID,
	).Scan(&id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create custom claim", err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Custom claim created"})
}

func (s *Service) handleUpdateCustomClaim(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	claimID := c.Param("claimId")
	var req struct {
		ClaimName            *string          `json:"claim_name"`
		SourceType           *string          `json:"source_type"`
		SourceValue          *string          `json:"source_value"`
		ClaimType            *string          `json:"claim_type"`
		IncludeInIDToken     *bool            `json:"include_in_id_token"`
		IncludeInAccessToken *bool            `json:"include_in_access_token"`
		IncludeInUserinfo    *bool            `json:"include_in_userinfo"`
		Condition            *json.RawMessage `json:"condition"`
		Enabled              *bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	// Build dynamic update
	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.ClaimName != nil {
		sets = append(sets, fmt.Sprintf("claim_name = $%d", argIdx))
		args = append(args, *req.ClaimName)
		argIdx++
	}
	if req.SourceType != nil {
		sets = append(sets, fmt.Sprintf("source_type = $%d", argIdx))
		args = append(args, *req.SourceType)
		argIdx++
	}
	if req.SourceValue != nil {
		sets = append(sets, fmt.Sprintf("source_value = $%d", argIdx))
		args = append(args, *req.SourceValue)
		argIdx++
	}
	if req.ClaimType != nil {
		sets = append(sets, fmt.Sprintf("claim_type = $%d", argIdx))
		args = append(args, *req.ClaimType)
		argIdx++
	}
	if req.IncludeInIDToken != nil {
		sets = append(sets, fmt.Sprintf("include_in_id_token = $%d", argIdx))
		args = append(args, *req.IncludeInIDToken)
		argIdx++
	}
	if req.IncludeInAccessToken != nil {
		sets = append(sets, fmt.Sprintf("include_in_access_token = $%d", argIdx))
		args = append(args, *req.IncludeInAccessToken)
		argIdx++
	}
	if req.IncludeInUserinfo != nil {
		sets = append(sets, fmt.Sprintf("include_in_userinfo = $%d", argIdx))
		args = append(args, *req.IncludeInUserinfo)
		argIdx++
	}
	if req.Condition != nil {
		sets = append(sets, fmt.Sprintf("condition = $%d", argIdx))
		args = append(args, *req.Condition)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	args = append(args, claimID, org.ID)
	// SECURITY: Column names in 'sets' are hardcoded string literals from the if-blocks above,
	// not user input. This is safe from SQL injection.
	query := fmt.Sprintf("UPDATE custom_claims_mappings SET %s WHERE id = $%d AND org_id = $%d",
		joinStrings(sets, ", "), argIdx, argIdx+1)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update custom claim", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Custom claim"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Custom claim updated"})
}

func (s *Service) handleDeleteCustomClaim(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, oerr := orgctx.From(c.Request.Context())
	if oerr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	claimID := c.Param("claimId")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM custom_claims_mappings WHERE id = $1 AND org_id = $2", claimID, org.ID)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete custom claim", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("Custom claim"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Custom claim deleted"})
}
