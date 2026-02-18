package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

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

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT sp.id, sp.provider_id, sp.provider_key, sp.display_name, sp.icon_url,
		        sp.button_color, sp.button_text, sp.auto_create_users, sp.auto_link_by_email,
		        sp.default_role, sp.allowed_domains, sp.attribute_mapping, sp.enabled,
		        sp.sort_order, sp.created_at, sp.updated_at,
		        COALESCE(ip.name, '') as idp_name
		 FROM social_providers sp
		 LEFT JOIN identity_providers ip ON sp.provider_id = ip.id
		 ORDER BY sp.sort_order`)
	if err != nil {
		s.logger.Error("Failed to list social providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list social providers"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO social_providers (provider_id, provider_key, display_name, icon_url,
		  button_color, button_text, auto_create_users, auto_link_by_email,
		  default_role, allowed_domains, attribute_mapping, enabled, sort_order)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING id`,
		req.ProviderID, req.ProviderKey, req.DisplayName, req.IconURL,
		req.ButtonColor, req.ButtonText, req.AutoCreateUsers, req.AutoLinkByEmail,
		req.DefaultRole, req.AllowedDomains, req.AttributeMapping, req.Enabled, req.SortOrder,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create social provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create social provider"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Social provider created"})
}

func (s *Service) handleGetSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var p SocialProvider
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, provider_id, provider_key, display_name, icon_url,
		        button_color, button_text, auto_create_users, auto_link_by_email,
		        default_role, allowed_domains, attribute_mapping, enabled,
		        sort_order, created_at, updated_at
		 FROM social_providers WHERE id = $1`, id,
	).Scan(&p.ID, &p.ProviderID, &p.ProviderKey, &p.DisplayName, &p.IconURL,
		&p.ButtonColor, &p.ButtonText, &p.AutoCreateUsers, &p.AutoLinkByEmail,
		&p.DefaultRole, &p.AllowedDomains, &p.AttributeMapping, &p.Enabled,
		&p.SortOrder, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Social provider not found"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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

	args = append(args, id)
	query := fmt.Sprintf("UPDATE social_providers SET %s WHERE id = $%d",
		joinStrings(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update social provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update social provider"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Social provider not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Social provider updated"})
}

func (s *Service) handleDeleteSocialProvider(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM social_providers WHERE id = $1", id)
	if err != nil {
		s.logger.Error("Failed to delete social provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete social provider"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Social provider not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Social provider deleted"})
}

// --- Federation Rules ---

func (s *Service) handleListFederationRules(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT fr.id, fr.name, fr.email_domain, fr.provider_id,
		        COALESCE(ip.name, '') as provider_name,
		        fr.priority, fr.auto_redirect, fr.enabled, fr.metadata,
		        fr.created_at, fr.updated_at
		 FROM federation_rules fr
		 LEFT JOIN identity_providers ip ON fr.provider_id = ip.id
		 ORDER BY fr.priority, fr.email_domain`)
	if err != nil {
		s.logger.Error("Failed to list federation rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list federation rules"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO federation_rules (name, email_domain, provider_id, priority, auto_redirect, enabled, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id`,
		req.Name, req.EmailDomain, req.ProviderID, req.Priority, req.AutoRedirect, req.Enabled, req.Metadata,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create federation rule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create federation rule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Federation rule created"})
}

func (s *Service) handleUpdateFederationRule(c *gin.Context) {
	if !requireAdmin(c) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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

	args = append(args, id)
	query := fmt.Sprintf("UPDATE federation_rules SET %s WHERE id = $%d",
		joinStrings(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update federation rule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update federation rule"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Federation rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Federation rule updated"})
}

func (s *Service) handleDeleteFederationRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM federation_rules WHERE id = $1", id)
	if err != nil {
		s.logger.Error("Failed to delete federation rule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete federation rule"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Federation rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Federation rule deleted"})
}

// --- User Identity Links ---

func (s *Service) handleListUserIdentityLinks(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	userID := c.Param("userId")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT uil.id, uil.user_id, uil.provider_id,
		        COALESCE(ip.name, '') as provider_name,
		        uil.external_id, uil.external_email, uil.external_username,
		        uil.display_name, uil.profile_data, uil.is_primary,
		        uil.linked_at, uil.last_used_at
		 FROM user_identity_links uil
		 LEFT JOIN identity_providers ip ON uil.provider_id = ip.id
		 WHERE uil.user_id = $1
		 ORDER BY uil.linked_at`, userID)
	if err != nil {
		s.logger.Error("Failed to list user identity links", zap.Error(err), zap.String("user_id", userID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list identity links"})
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
	userID := c.Param("userId")

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
		s.logger.Error("Failed to delete identity link", zap.Error(err), zap.String("link_id", linkID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete identity link"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity link not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Identity link deleted"})
}

// --- Custom Claims Mappings ---

func (s *Service) handleListCustomClaims(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	appID := c.Param("appId")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, application_id, claim_name, source_type, source_value,
		        claim_type, include_in_id_token, include_in_access_token,
		        include_in_userinfo, condition, enabled, created_at, updated_at
		 FROM custom_claims_mappings WHERE application_id = $1
		 ORDER BY claim_name`, appID)
	if err != nil {
		s.logger.Error("Failed to list custom claims", zap.Error(err), zap.String("application_id", appID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list custom claims"})
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

	appID := c.Param("appId")
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO custom_claims_mappings (application_id, claim_name, source_type, source_value,
		  claim_type, include_in_id_token, include_in_access_token, include_in_userinfo, condition, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id`,
		appID, req.ClaimName, req.SourceType, req.SourceValue,
		req.ClaimType, req.IncludeInIDToken, req.IncludeInAccessToken,
		req.IncludeInUserinfo, req.Condition, req.Enabled,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create custom claim", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create custom claim"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Custom claim created"})
}

func (s *Service) handleUpdateCustomClaim(c *gin.Context) {
	if !requireAdmin(c) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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

	args = append(args, claimID)
	query := fmt.Sprintf("UPDATE custom_claims_mappings SET %s WHERE id = $%d",
		joinStrings(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update custom claim", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update custom claim"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Custom claim not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Custom claim updated"})
}

func (s *Service) handleDeleteCustomClaim(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	claimID := c.Param("claimId")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM custom_claims_mappings WHERE id = $1", claimID)
	if err != nil {
		s.logger.Error("Failed to delete custom claim", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete custom claim"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Custom claim not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Custom claim deleted"})
}

