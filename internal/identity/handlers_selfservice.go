// Package identity provides self-service handlers for personal access tokens and consent management
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PersonalAccessToken represents a user's API key
type PersonalAccessToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used_at,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

// handleListUserPATs returns all personal access tokens for the authenticated user
func (s *Service) handleListUserPATs(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, name, key_prefix, scopes, expires_at, last_used_at, status, created_at
		FROM api_keys WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		s.logger.Error("Failed to list user PATs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tokens"})
		return
	}
	defer rows.Close()

	tokens := []PersonalAccessToken{}
	for rows.Next() {
		var t PersonalAccessToken
		if err := rows.Scan(&t.ID, &t.Name, &t.KeyPrefix, &t.Scopes, &t.ExpiresAt, &t.LastUsed, &t.Status, &t.CreatedAt); err != nil {
			continue
		}
		tokens = append(tokens, t)
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// handleCreateUserPAT creates a new personal access token for the authenticated user
func (s *Service) handleCreateUserPAT(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Name      string   `json:"name" binding:"required"`
		Scopes    []string `json:"scopes"`
		ExpiresAt *string  `json:"expires_at,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	// Parse optional expiry
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid expires_at format, use RFC3339"})
			return
		}
		expiresAt = &t
	}

	if req.Scopes == nil {
		req.Scopes = []string{"read"}
	}

	// Generate token
	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	plaintext := "oidx_" + hex.EncodeToString(randBytes)
	keyPrefix := plaintext[:12]
	hash := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(hash[:])

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO api_keys (id, name, key_prefix, key_hash, user_id, scopes, expires_at, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, id, req.Name, keyPrefix, keyHash, userID, req.Scopes, expiresAt, "active", now)
	if err != nil {
		s.logger.Error("Failed to create PAT", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	s.logger.Info("Personal access token created",
		zap.String("user_id", userID),
		zap.String("token_name", req.Name))

	c.JSON(http.StatusCreated, gin.H{
		"token": plaintext,
		"api_key": PersonalAccessToken{
			ID:        id,
			Name:      req.Name,
			KeyPrefix: keyPrefix,
			Scopes:    req.Scopes,
			ExpiresAt: expiresAt,
			Status:    "active",
			CreatedAt: now,
		},
	})
}

// handleRevokeUserPAT revokes a personal access token owned by the authenticated user
func (s *Service) handleRevokeUserPAT(c *gin.Context) {
	userID := c.GetString("user_id")
	keyID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Only revoke if the key belongs to this user
	var keyHash string
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		UPDATE api_keys SET status = 'revoked'
		WHERE id = $1 AND user_id = $2 AND status = 'active'
		RETURNING key_hash
	`, keyID, userID).Scan(&keyHash)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found or already revoked"})
		return
	}

	// Clear Redis cache
	s.redis.Client.Del(c.Request.Context(), "apikey:"+keyHash)

	s.logger.Info("Personal access token revoked",
		zap.String("user_id", userID),
		zap.String("key_id", keyID))

	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

// UserConsent represents an authorized application for a user
type UserConsent struct {
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	LogoURI      string    `json:"logo_uri,omitempty"`
	Scopes       []string  `json:"scopes"`
	AuthorizedAt time.Time `json:"authorized_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// handleListUserConsents returns all apps the user has authorized via OAuth
func (s *Service) handleListUserConsents(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT rt.client_id,
		       COALESCE(oc.name, rt.client_id) AS client_name,
		       COALESCE(oc.logo_uri, '') AS logo_uri,
		       rt.scope,
		       MIN(rt.created_at) AS authorized_at,
		       MAX(rt.created_at) AS last_used_at
		FROM oauth_refresh_tokens rt
		LEFT JOIN oauth_clients oc ON oc.client_id = rt.client_id
		WHERE rt.user_id = $1 AND rt.expires_at > NOW()
		GROUP BY rt.client_id, oc.name, oc.logo_uri
		ORDER BY authorized_at DESC
	`, userID)
	if err != nil {
		s.logger.Error("Failed to list user consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list authorized apps"})
		return
	}
	defer rows.Close()

	consents := []UserConsent{}
	for rows.Next() {
		var consent UserConsent
		var scopeStr string
		if err := rows.Scan(&consent.ClientID, &consent.ClientName, &consent.LogoURI,
			&scopeStr, &consent.AuthorizedAt, &consent.LastUsedAt); err != nil {
			continue
		}
		consent.Scopes = strings.Fields(scopeStr)
		consents = append(consents, consent)
	}

	c.JSON(http.StatusOK, gin.H{"consents": consents})
}

// handleRevokeUserConsent revokes all tokens for a given app, effectively removing authorization
func (s *Service) handleRevokeUserConsent(c *gin.Context) {
	userID := c.GetString("user_id")
	clientID := c.Param("client_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Delete refresh tokens
	_, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND client_id = $2",
		userID, clientID)
	if err != nil {
		s.logger.Error("Failed to revoke consent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke authorization"})
		return
	}

	// Also delete access tokens
	s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM oauth_access_tokens WHERE user_id = $1 AND client_id = $2",
		userID, clientID)

	s.logger.Info("User consent revoked",
		zap.String("user_id", userID),
		zap.String("client_id", clientID))

	c.JSON(http.StatusOK, gin.H{"message": "Authorization revoked successfully"})
}
