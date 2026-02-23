// Package oauth provides user consent management for OAuth/OIDC
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

var (
	// ErrConsentNotFound is returned when consent is not found
	ErrConsentNotFound = errors.New("consent_not_found")
	// ErrConsentRequired is returned when user consent is required
	ErrConsentRequired = errors.New("consent_required")
	// ErrConsentRevoked is returned when consent has been revoked
	ErrConsentRevoked = errors.New("consent_revoked")
	// ErrInvalidConsentData is returned when consent data is invalid
	ErrInvalidConsentData = errors.New("invalid_consent_data")
)

const (
	// ConsentGranted indicates the user has granted consent
	ConsentGranted = "granted"
	// ConsentDenied indicates the user has denied consent
	ConsentDenied = "denied"
	// ConsentRevoked indicates the user has revoked previously granted consent
	ConsentRevoked = "revoked"
)

// ConsentRecord represents a user's consent for a specific client and scopes
type ConsentRecord struct {
	ID           string     `json:"id" db:"id"`
	UserID       string     `json:"user_id" db:"user_id"`
	ClientID     string     `json:"client_id" db:"client_id"`
	Scopes       []string   `json:"scopes" db:"scopes"`
	Claims       []string   `json:"claims,omitempty" db:"claims"`
	Status       string     `json:"status" db:"status"` // granted, denied, revoked
	GrantedAt    time.Time  `json:"granted_at" db:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	ClientName   string     `json:"client_name,omitempty"` // Not stored, populated from client
}

// ConsentRequest represents a consent request from the authorization endpoint
type ConsentRequest struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	ClientID     string    `json:"client_id"`
	RedirectURI  string    `json:"redirect_uri"`
	RequestedScopes []string `json:"requested_scopes"`
	GrantedScopes []string `json:"granted_scopes"`
	DeniedScopes []string `json:"denied_scopes"`
	Nonce        string    `json:"nonce,omitempty"`
	State        string    `json:"state,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ConsentUIResponse represents the data needed for the consent UI
type ConsentUIResponse struct {
	SessionID        string                 `json:"session_id"`
	ClientID         string                 `json:"client_id"`
	ClientName       string                 `json:"client_name"`
	ClientLogoURI    string                 `json:"client_logo_uri,omitempty"`
	ClientPolicyURI  string                 `json:"client_policy_uri,omitempty"`
	ClientTOSURI     string                 `json:"client_tos_uri,omitempty"`
	RedirectURI      string                 `json:"redirect_uri"`
	RequestedScopes  []ScopeDisplay         `json:"requested_scopes"`
	PreviousConsent  *ConsentRecord         `json:"previous_consent,omitempty"`
	UserInfo         map[string]interface{} `json:"user_info,omitempty"`
	State            string                 `json:"state,omitempty"`
}

// ScopeDisplay represents a scope for display in the consent UI
type ScopeDisplay struct {
	Scope        string `json:"scope"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Required     bool   `json:"required"`
	PreviouslyGranted bool `json:"previously_granted,omitempty"`
}

// ScopeDefinitions defines the display information for supported scopes
var ScopeDefinitions = map[string]ScopeDisplay{
	"openid": {
		Scope:       "openid",
		Name:        "OpenID Connect",
		Description: "Verify your identity securely using OpenID Connect",
		Required:    true,
	},
	"profile": {
		Scope:       "profile",
		Name:        "Basic Profile",
		Description: "Access your name, username, and other basic profile information",
		Required:    false,
	},
	"email": {
		Scope:       "email",
		Name:        "Email Address",
		Description: "Access your email address",
		Required:    false,
	},
	"phone": {
		Scope:       "phone",
		Name:        "Phone Number",
		Description: "Access your phone number",
		Required:    false,
	},
	"address": {
		Scope:       "address",
		Name:        "Address",
		Description: "Access your postal address",
		Required:    false,
	},
	"offline_access": {
		Scope:       "offline_access",
		Name:        "Offline Access",
		Description: "Maintain access to your data when you are not actively using the application",
		Required:    false,
	},
}

// ConsentManager manages user consent for OAuth/OIDC clients
type ConsentManager struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewConsentManager creates a new consent manager
func NewConsentManager(db *database.PostgresDB, logger *zap.Logger) *ConsentManager {
	return &ConsentManager{
		db:     db,
		logger: logger.With(zap.String("component", "consent")),
	}
}

// CheckExistingConsent checks if the user has previously granted consent for this client and scopes
// Returns the consent record if found, or nil if consent is required
func (m *ConsentManager) CheckExistingConsent(ctx context.Context, userID, clientID string, requestedScopes []string) (*ConsentRecord, error) {
	// Query for existing granted consent
	var consent ConsentRecord
	var scopesJSON []byte
	var metadataJSON []byte
	var expiresAt, revokedAt, lastUsedAt *time.Time

	err := m.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, client_id, scopes, claims, status,
		       granted_at, expires_at, revoked_at, last_used_at, metadata
		FROM oauth_consent
		WHERE user_id = $1 AND client_id = $2 AND status = 'granted'
		ORDER BY granted_at DESC
		LIMIT 1
	`, userID, clientID).Scan(
		&consent.ID, &consent.UserID, &consent.ClientID, &scopesJSON,
		&consent.Claims, &consent.Status, &consent.GrantedAt, &expiresAt,
		&revokedAt, &lastUsedAt, &metadataJSON,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No existing consent found
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query consent: %w", err)
	}

	// Check if consent has expired
	if expiresAt != nil && time.Now().After(*expiresAt) {
		m.logger.Debug("Existing consent expired",
			zap.String("user_id", userID),
			zap.String("client_id", clientID))
		return nil, nil
	}

	// Parse scopes JSON
	if err := json.Unmarshal(scopesJSON, &consent.Scopes); err != nil {
		return nil, fmt.Errorf("failed to parse scopes: %w", err)
	}

	consent.ExpiresAt = expiresAt
	consent.RevokedAt = revokedAt
	consent.LastUsedAt = lastUsedAt

	// Parse metadata if present
	if metadataJSON != nil {
		if err := json.Unmarshal(metadataJSON, &consent.Metadata); err != nil {
			m.logger.Warn("Failed to parse consent metadata", zap.Error(err))
		}
	}

	// Check if all requested scopes are covered by the existing consent
	grantedScopeSet := make(map[string]bool)
	for _, s := range consent.Scopes {
		grantedScopeSet[s] = true
	}

	for _, requested := range requestedScopes {
		if !grantedScopeSet[requested] {
			// New scope requested, need to update consent
			m.logger.Debug("New scope requested, consent update required",
				zap.String("user_id", userID),
				zap.String("client_id", clientID),
				zap.String("new_scope", requested))
			return nil, nil
		}
	}

	// All scopes are covered by existing consent
	m.logger.Debug("Existing consent covers requested scopes",
		zap.String("user_id", userID),
		zap.String("client_id", clientID))

	return &consent, nil
}

// StoreConsent stores a new consent record
func (m *ConsentManager) StoreConsent(ctx context.Context, consent *ConsentRecord) error {
	consent.GrantedAt = time.Now()
	consent.Status = ConsentGranted

	scopesJSON, err := json.Marshal(consent.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	claimsJSON, err := json.Marshal(consent.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	metadataJSON, err := json.Marshal(consent.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO oauth_consent (
			id, user_id, client_id, scopes, claims, status,
			granted_at, expires_at, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, client_id) DO UPDATE SET
			scopes = EXCLUDED.scopes,
			claims = EXCLUDED.claims,
			status = EXCLUDED.status,
			granted_at = EXCLUDED.granted_at,
			expires_at = EXCLUDED.expires_at,
			metadata = EXCLUDED.metadata
	`

	_, err = m.db.Pool.Exec(ctx, query,
		consent.ID, consent.UserID, consent.ClientID, scopesJSON,
		claimsJSON, consent.Status, consent.GrantedAt, consent.ExpiresAt, metadataJSON)

	if err != nil {
		return fmt.Errorf("failed to store consent: %w", err)
	}

	m.logger.Info("Stored user consent",
		zap.String("user_id", consent.UserID),
		zap.String("client_id", consent.ClientID),
		zap.Strings("scopes", consent.Scopes))

	return nil
}

// RevokeConsent revokes a previously granted consent
func (m *ConsentManager) RevokeConsent(ctx context.Context, userID, clientID string) error {
	now := time.Now()

	result, err := m.db.Pool.Exec(ctx, `
		UPDATE oauth_consent
		SET status = 'revoked', revoked_at = $1
		WHERE user_id = $2 AND client_id = $3 AND status = 'granted'
	`, now, userID, clientID)

	if err != nil {
		return fmt.Errorf("failed to revoke consent: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrConsentNotFound
	}

	m.logger.Info("Revoked user consent",
		zap.String("user_id", userID),
		zap.String("client_id", clientID))

	return nil
}

// GetConsent retrieves a consent record by ID
func (m *ConsentManager) GetConsent(ctx context.Context, consentID string) (*ConsentRecord, error) {
	var consent ConsentRecord
	var scopesJSON, claimsJSON, metadataJSON []byte
	var expiresAt, revokedAt, lastUsedAt *time.Time

	err := m.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, client_id, scopes, claims, status,
		       granted_at, expires_at, revoked_at, last_used_at, metadata
		FROM oauth_consent WHERE id = $1
	`, consentID).Scan(
		&consent.ID, &consent.UserID, &consent.ClientID, &scopesJSON,
		&claimsJSON, &consent.Status, &consent.GrantedAt, &expiresAt,
		&revokedAt, &lastUsedAt, &metadataJSON,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConsentNotFound
		}
		return nil, fmt.Errorf("failed to query consent: %w", err)
	}

	if err := json.Unmarshal(scopesJSON, &consent.Scopes); err != nil {
		return nil, fmt.Errorf("failed to parse scopes: %w", err)
	}

	if err := json.Unmarshal(claimsJSON, &consent.Claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	consent.ExpiresAt = expiresAt
	consent.RevokedAt = revokedAt
	consent.LastUsedAt = lastUsedAt

	if metadataJSON != nil {
		if err := json.Unmarshal(metadataJSON, &consent.Metadata); err != nil {
			m.logger.Warn("Failed to parse consent metadata", zap.Error(err))
		}
	}

	return &consent, nil
}

// ListUserConsents lists all consent records for a user
func (m *ConsentManager) ListUserConsents(ctx context.Context, userID string, includeRevoked bool) ([]*ConsentRecord, error) {
	query := `
		SELECT id, user_id, client_id, scopes, claims, status,
		       granted_at, expires_at, revoked_at, last_used_at, metadata
		FROM oauth_consent WHERE user_id = $1
	`

	args := []interface{}{userID}

	if !includeRevoked {
		query += " AND status != 'revoked'"
	}

	query += " ORDER BY granted_at DESC"

	rows, err := m.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list consents: %w", err)
	}
	defer rows.Close()

	var consents []*ConsentRecord
	for rows.Next() {
		var consent ConsentRecord
		var scopesJSON, claimsJSON, metadataJSON []byte
		var expiresAt, revokedAt, lastUsedAt *time.Time

		err := rows.Scan(
			&consent.ID, &consent.UserID, &consent.ClientID, &scopesJSON,
			&claimsJSON, &consent.Status, &consent.GrantedAt, &expiresAt,
			&revokedAt, &lastUsedAt, &metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan consent: %w", err)
		}

		if err := json.Unmarshal(scopesJSON, &consent.Scopes); err != nil {
			return nil, fmt.Errorf("failed to parse scopes: %w", err)
		}

		if err := json.Unmarshal(claimsJSON, &consent.Claims); err != nil {
			return nil, fmt.Errorf("failed to parse claims: %w", err)
		}

		consent.ExpiresAt = expiresAt
		consent.RevokedAt = revokedAt
		consent.LastUsedAt = lastUsedAt

		if metadataJSON != nil {
			if err := json.Unmarshal(metadataJSON, &consent.Metadata); err != nil {
				m.logger.Warn("Failed to parse consent metadata", zap.Error(err))
			}
		}

		consents = append(consents, &consent)
	}

	return consents, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a consent record
func (m *ConsentManager) UpdateLastUsed(ctx context.Context, userID, clientID string) error {
	now := time.Now()

	_, err := m.db.Pool.Exec(ctx, `
		UPDATE oauth_consent
		SET last_used_at = $1
		WHERE user_id = $2 AND client_id = $3 AND status = 'granted'
	`, now, userID, clientID)

	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	return nil
}

// BuildConsentUIResponse builds the data needed for the consent UI
func (m *ConsentManager) BuildConsentUIResponse(
	ctx context.Context,
	req *ConsentRequest,
	client *OAuthClient,
	userInfo map[string]interface{},
) (*ConsentUIResponse, error) {
	response := &ConsentUIResponse{
		SessionID:       req.SessionID,
		ClientID:        req.ClientID,
		ClientName:      client.Name,
		ClientLogoURI:   client.LogoURI,
		ClientPolicyURI: client.PolicyURI,
		ClientTOSURI:    client.TOSUri,
		RedirectURI:     req.RedirectURI,
		UserInfo:        userInfo,
		State:           req.State,
	}

	// Build scope display information
	response.RequestedScopes = make([]ScopeDisplay, 0, len(req.RequestedScopes))

	// Check for previous consent
	previousConsent, _ := m.CheckExistingConsent(ctx, req.UserID, req.ClientID, req.RequestedScopes)
	if previousConsent != nil {
		response.PreviousConsent = previousConsent
	}

	// Build scope display list
	grantedScopeSet := make(map[string]bool)
	if previousConsent != nil {
		for _, s := range previousConsent.Scopes {
			grantedScopeSet[s] = true
		}
	}

	for _, scope := range req.RequestedScopes {
		display := ScopeDefinitions[scope]
		display.PreviouslyGranted = grantedScopeSet[scope]
		response.RequestedScopes = append(response.RequestedScopes, display)
	}

	return response, nil
}

// CleanupExpiredConsents removes consent records that are past their expiration date
func (m *ConsentManager) CleanupExpiredConsents(ctx context.Context) (int64, error) {
	result, err := m.db.Pool.Exec(ctx, `
		DELETE FROM oauth_consent
		WHERE status = 'revoked'
		AND (revoked_at < NOW() - INTERVAL '30 days' OR
		     expires_at IS NOT NULL AND expires_at < NOW())
	`)

	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired consents: %w", err)
	}

	count := result.RowsAffected()
	if count > 0 {
		m.logger.Info("Cleaned up expired consent records",
			zap.Int64("count", count))
	}

	return count, nil
}

// EnsureConsentTable creates the oauth_consent table if it doesn't exist
func (m *ConsentManager) EnsureConsentTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS oauth_consent (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id VARCHAR(255) NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			scopes TEXT[] NOT NULL,
			claims TEXT[] DEFAULT '{}',
			status VARCHAR(20) NOT NULL DEFAULT 'granted',
			granted_at TIMESTAMP NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			last_used_at TIMESTAMP,
			metadata JSONB,
			UNIQUE(user_id, client_id)
		);

		CREATE INDEX IF NOT EXISTS idx_oauth_consent_user_id ON oauth_consent(user_id);
		CREATE INDEX IF NOT EXISTS idx_oauth_consent_client_id ON oauth_consent(client_id);
		CREATE INDEX IF NOT EXISTS idx_oauth_consent_status ON oauth_consent(status);
		CREATE INDEX IF NOT EXISTS idx_oauth_consent_expires_at ON oauth_consent(expires_at);
	`

	_, err := m.db.Pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create oauth_consent table: %w", err)
	}

	return nil
}

// ParseScopeString parses a space-separated scope string into a slice
func ParseScopeString(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}

	parts := strings.Split(scopeStr, " ")
	scopes := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			scopes = append(scopes, part)
		}
	}

	return scopes
}

// BuildScopeString creates a space-separated scope string from a slice
func BuildScopeString(scopes []string) string {
	return strings.Join(scopes, " ")
}

// IsConsentRequired checks if user consent is required for the given request
func IsConsentRequired(scopes []string, previousConsent *ConsentRecord) bool {
	if previousConsent == nil {
		return true
	}

	// Check if all requested scopes are in the previous consent
	grantedScopes := make(map[string]bool)
	for _, s := range previousConsent.Scopes {
		grantedScopes[s] = true
	}

	for _, requested := range scopes {
		if !grantedScopes[requested] {
			return true
		}
	}

	return false
}

// NormalizeScopes normalizes and deduplicates a list of scopes
func NormalizeScopes(scopes []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" && !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	return result
}

// GetRequiredScopes returns scopes that are required (must be granted)
func GetRequiredScopes() []string {
	required := []string{}
	for _, def := range ScopeDefinitions {
		if def.Required {
			required = append(required, def.Scope)
		}
	}
	return required
}
