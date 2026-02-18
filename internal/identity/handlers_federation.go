package identity

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// handleFederationDiscover is a PUBLIC endpoint that returns the IdP to redirect to based on email domain.
func (s *Service) handleFederationDiscover(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	parts := strings.SplitN(req.Email, "@", 2)
	if len(parts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}
	domain := strings.ToLower(parts[1])

	var providerID, providerName, issuerURL string
	var autoRedirect bool
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT fr.provider_id, ip.name, ip.issuer_url, fr.auto_redirect
		 FROM federation_rules fr
		 JOIN identity_providers ip ON fr.provider_id = ip.id
		 WHERE fr.email_domain = $1 AND fr.enabled = true
		 ORDER BY fr.priority LIMIT 1`, domain).Scan(&providerID, &providerName, &issuerURL, &autoRedirect)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"found": false, "message": "No federation rule for this domain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"found":         true,
		"provider_id":   providerID,
		"provider_name": providerName,
		"issuer_url":    issuerURL,
		"auto_redirect": autoRedirect,
	})
}

// handleGetMyIdentityLinks returns the current user's linked external identities.
func (s *Service) handleGetMyIdentityLinks(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT uil.id, uil.provider_id, ip.name as provider_name,
			uil.external_id, uil.external_email, uil.external_username,
			uil.display_name, uil.profile_data, uil.is_primary, uil.linked_at, uil.last_used_at
		 FROM user_identity_links uil
		 LEFT JOIN identity_providers ip ON uil.provider_id = ip.id
		 WHERE uil.user_id = $1 ORDER BY uil.linked_at`, userID)
	if err != nil {
		s.logger.Error("Failed to list identity links", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list identity links"})
		return
	}
	defer rows.Close()

	type link struct {
		ID               string          `json:"id"`
		ProviderID       string          `json:"provider_id"`
		ProviderName     *string         `json:"provider_name"`
		ExternalID       string          `json:"external_id"`
		ExternalEmail    *string         `json:"external_email"`
		ExternalUsername *string         `json:"external_username"`
		DisplayName      *string         `json:"display_name"`
		ProfileData      json.RawMessage `json:"profile_data"`
		IsPrimary        bool            `json:"is_primary"`
		LinkedAt         time.Time       `json:"linked_at"`
		LastUsedAt       *time.Time      `json:"last_used_at"`
	}

	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.ID, &l.ProviderID, &l.ProviderName,
			&l.ExternalID, &l.ExternalEmail, &l.ExternalUsername,
			&l.DisplayName, &l.ProfileData, &l.IsPrimary, &l.LinkedAt, &l.LastUsedAt); err != nil {
			continue
		}
		links = append(links, l)
	}
	if links == nil {
		links = []link{}
	}
	c.JSON(http.StatusOK, gin.H{"data": links})
}

// handleUnlinkMyIdentity removes one of the current user's linked external identities.
func (s *Service) handleUnlinkMyIdentity(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	linkID := c.Param("linkId")

	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM user_identity_links WHERE id = $1 AND user_id = $2", linkID, userID)
	if err != nil {
		s.logger.Error("Failed to unlink identity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unlink identity"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity link not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Identity unlinked"})
}
