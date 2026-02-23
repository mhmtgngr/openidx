// Package oauth provides OAuth 2.0 client management functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	commonerrors "github.com/openidx/openidx/internal/common/errors"
)

var (
	// ErrClientNotFound is returned when a client is not found
	ErrClientNotFound = errors.New("client_not_found")
	// ErrClientAlreadyExists is returned when attempting to create a duplicate client
	ErrClientAlreadyExists = errors.New("client_already_exists")
	// ErrInvalidClientCredentials is returned when client authentication fails
	ErrInvalidClientCredentials = errors.New("invalid_client")
	// ErrInvalidRedirectURI is returned when redirect URI is not registered
	ErrInvalidRedirectURI = errors.New("invalid_redirect_uri")
)

// Client represents an OAuth 2.0 client application
type Client struct {
	ID                   string    `json:"id"`
	ClientID             string    `json:"client_id"`
	ClientSecretHash     string    `json:"-"` // bcrypt hash, never exposed in JSON
	ClientSecretPlain    string    `json:"client_secret,omitempty"` // Only shown on creation
	Name                 string    `json:"name"`
	Description          string    `json:"description,omitempty"`
	TenantID             string    `json:"tenant_id"`
	RedirectURIs         []string  `json:"redirect_uris"`
	GrantTypes           []string  `json:"grant_types"`
	Scopes               []string  `json:"scopes"`
	ClientAuthentication string    `json:"client_authentication"` // client_secret_basic, client_secret_post, none
	PKCERequired         bool      `json:"pkce_required"`
	AccessTokenLifetime  int       `json:"access_token_lifetime"`  // seconds, 0 = default
	RefreshTokenLifetime int       `json:"refresh_token_lifetime"` // seconds, 0 = default
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// CreateClientRequest represents a request to create a new OAuth client
type CreateClientRequest struct {
	Name                 string   `json:"name" binding:"required"`
	Description          string   `json:"description,omitempty"`
	TenantID             string   `json:"tenant_id,omitempty"`
	RedirectURIs         []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes           []string `json:"grant_types"`
	Scopes               []string `json:"scopes"`
	ClientAuthentication string   `json:"client_authentication,omitempty"`
	PKCERequired         bool     `json:"pkce_required,omitempty"`
	AccessTokenLifetime  int      `json:"access_token_lifetime,omitempty"`
	RefreshTokenLifetime int      `json:"refresh_token_lifetime,omitempty"`
}

// UpdateClientRequest represents a request to update an OAuth client
type UpdateClientRequest struct {
	Name                 *string   `json:"name,omitempty"`
	Description          *string   `json:"description,omitempty"`
	RedirectURIs         *[]string `json:"redirect_uris,omitempty"`
	GrantTypes           *[]string `json:"grant_types,omitempty"`
	Scopes               *[]string `json:"scopes,omitempty"`
	ClientAuthentication *string   `json:"client_authentication,omitempty"`
	PKCERequired         *bool     `json:"pkce_required,omitempty"`
	AccessTokenLifetime  *int      `json:"access_token_lifetime,omitempty"`
	RefreshTokenLifetime *int      `json:"refresh_token_lifetime,omitempty"`
}

// ClientRepository handles OAuth client persistence
type ClientRepository struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewClientRepository creates a new OAuth client repository
func NewClientRepository(db *database.PostgresDB, logger *zap.Logger) *ClientRepository {
	return &ClientRepository{
		db:     db,
		logger: logger.With(zap.String("repository", "oauth_client")),
	}
}

// Create creates a new OAuth client with a generated client ID and secret
func (r *ClientRepository) Create(ctx context.Context, req *CreateClientRequest) (*Client, error) {
	// Generate client ID and secret
	clientID := generateClientID()
	clientSecret := generateClientSecret()

	// Hash the client secret using SHA-256 (for client_secret_basic validation)
	// Using a simple hash here since OAuth client secrets are long random strings
	// In production, consider using bcrypt for additional security
	secretHash := hashClientSecret(clientSecret)

	// Set defaults
	if req.GrantTypes == nil || len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if req.Scopes == nil || len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile"}
	}
	if req.ClientAuthentication == "" {
		req.ClientAuthentication = "client_secret_basic"
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	// Validate grant types
	validGrantTypes := map[string]bool{
		"authorization_code": true,
		"client_credentials": true,
		"refresh_token":      true,
		"password":           true, // Not recommended for public clients
	}
	for _, gt := range req.GrantTypes {
		if !validGrantTypes[gt] {
			return nil, commonerrors.BadRequest(fmt.Sprintf("invalid grant_type: %s", gt))
		}
	}

	now := time.Now()

	client := &Client{
		ID:                   generateUUID(),
		ClientID:             clientID,
		ClientSecretHash:     secretHash,
		ClientSecretPlain:    clientSecret, // Only for return
		Name:                 req.Name,
		Description:          req.Description,
		TenantID:             req.TenantID,
		RedirectURIs:         req.RedirectURIs,
		GrantTypes:           req.GrantTypes,
		Scopes:               req.Scopes,
		ClientAuthentication: req.ClientAuthentication,
		PKCERequired:         req.PKCERequired,
		AccessTokenLifetime:  req.AccessTokenLifetime,
		RefreshTokenLifetime: req.RefreshTokenLifetime,
		CreatedAt:            now,
		UpdatedAt:           now,
	}

	// Insert into database
	query := `
		INSERT INTO oauth_clients (
			id, client_id, client_secret_hash, name, description, tenant_id,
			redirect_uris, grant_types, scopes, client_authentication,
			pkce_required, access_token_lifetime, refresh_token_lifetime,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id
	`

	_, err := r.db.Pool.Exec(ctx, query,
		client.ID, client.ClientID, client.ClientSecretHash, client.Name,
		client.Description, client.TenantID, client.RedirectURIs,
		client.GrantTypes, client.Scopes, client.ClientAuthentication,
		client.PKCERequired, client.AccessTokenLifetime, client.RefreshTokenLifetime,
		client.CreatedAt, client.UpdatedAt,
	)

	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			// Unique constraint violation
			return nil, commonerrors.Conflict("Client ID already exists").WithMetadata("client_id", clientID)
		}
		r.logger.Error("Failed to create OAuth client", zap.Error(err))
		return nil, commonerrors.DatabaseError("insert oauth_client", err)
	}

	r.logger.Info("Created OAuth client",
		zap.String("client_id", clientID),
		zap.String("name", client.Name))

	return client, nil
}

// GetByID retrieves a client by its database ID
func (r *ClientRepository) GetByID(ctx context.Context, id string) (*Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, description, tenant_id,
		       redirect_uris, grant_types, scopes, client_authentication,
		       pkce_required, access_token_lifetime, refresh_token_lifetime,
		       created_at, updated_at
		FROM oauth_clients
		WHERE id = $1
	`

	var client Client
	err := r.db.Pool.QueryRow(ctx, query, id).Scan(
		&client.ID, &client.ClientID, &client.ClientSecretHash, &client.Name,
		&client.Description, &client.TenantID, &client.RedirectURIs,
		&client.GrantTypes, &client.Scopes, &client.ClientAuthentication,
		&client.PKCERequired, &client.AccessTokenLifetime,
		&client.RefreshTokenLifetime, &client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, commonerrors.NotFound("OAuth client").WithMetadata("id", id)
		}
		r.logger.Error("Failed to get OAuth client by ID", zap.Error(err))
		return nil, commonerrors.DatabaseError("select oauth_client", err)
	}

	return &client, nil
}

// GetByClientID retrieves a client by its client_id
func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, description, tenant_id,
		       redirect_uris, grant_types, scopes, client_authentication,
		       pkce_required, access_token_lifetime, refresh_token_lifetime,
		       created_at, updated_at
		FROM oauth_clients
		WHERE client_id = $1
	`

	var client Client
	err := r.db.Pool.QueryRow(ctx, query, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientSecretHash, &client.Name,
		&client.Description, &client.TenantID, &client.RedirectURIs,
		&client.GrantTypes, &client.Scopes, &client.ClientAuthentication,
		&client.PKCERequired, &client.AccessTokenLifetime,
		&client.RefreshTokenLifetime, &client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, commonerrors.Unauthorized("Invalid client").WithMetadata("client_id", clientID)
		}
		r.logger.Error("Failed to get OAuth client by client_id", zap.Error(err))
		return nil, commonerrors.DatabaseError("select oauth_client by client_id", err)
	}

	return &client, nil
}

// List retrieves clients with optional filtering by tenant_id
func (r *ClientRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]*Client, int, error) {
	// Build query with optional tenant filter
	baseQuery := `SELECT id, client_id, client_secret_hash, name, description, tenant_id,
	              redirect_uris, grant_types, scopes, client_authentication,
	              pkce_required, access_token_lifetime, refresh_token_lifetime,
	              created_at, updated_at FROM oauth_clients`
	countQuery := `SELECT COUNT(*) FROM oauth_clients`
	args := []interface{}{}
	conditions := []string{}

	if tenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)+1))
		args = append(args, tenantID)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	var total int
	err := r.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("Failed to count OAuth clients", zap.Error(err))
		return nil, 0, commonerrors.DatabaseError("count oauth_clients", err)
	}

	// Add pagination
	baseQuery += " ORDER BY created_at DESC"
	if limit > 0 {
		baseQuery += fmt.Sprintf(" LIMIT $%d", len(args)+1)
		args = append(args, limit)
	}
	if offset > 0 {
		baseQuery += fmt.Sprintf(" OFFSET $%d", len(args)+1)
		args = append(args, offset)
	}

	rows, err := r.db.Pool.Query(ctx, baseQuery, args...)
	if err != nil {
		r.logger.Error("Failed to list OAuth clients", zap.Error(err))
		return nil, 0, commonerrors.DatabaseError("list oauth_clients", err)
	}
	defer rows.Close()

	clients := []*Client{}
	for rows.Next() {
		var client Client
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.ClientSecretHash, &client.Name,
			&client.Description, &client.TenantID, &client.RedirectURIs,
			&client.GrantTypes, &client.Scopes, &client.ClientAuthentication,
			&client.PKCERequired, &client.AccessTokenLifetime,
			&client.RefreshTokenLifetime, &client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			return nil, 0, commonerrors.DatabaseError("scan oauth_client", err)
		}
		clients = append(clients, &client)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, commonerrors.DatabaseError("iterate oauth_clients", err)
	}

	return clients, total, nil
}

// Update updates an existing OAuth client
func (r *ClientRepository) Update(ctx context.Context, id string, req *UpdateClientRequest) (*Client, error) {
	// Get existing client
	client, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.Description != nil {
		client.Description = *req.Description
	}
	if req.RedirectURIs != nil {
		if len(*req.RedirectURIs) == 0 {
			return nil, commonerrors.BadRequest("redirect_uris cannot be empty")
		}
		client.RedirectURIs = *req.RedirectURIs
	}
	if req.GrantTypes != nil {
		client.GrantTypes = *req.GrantTypes
	}
	if req.Scopes != nil {
		client.Scopes = *req.Scopes
	}
	if req.ClientAuthentication != nil {
		client.ClientAuthentication = *req.ClientAuthentication
	}
	if req.PKCERequired != nil {
		client.PKCERequired = *req.PKCERequired
	}
	if req.AccessTokenLifetime != nil {
		client.AccessTokenLifetime = *req.AccessTokenLifetime
	}
	if req.RefreshTokenLifetime != nil {
		client.RefreshTokenLifetime = *req.RefreshTokenLifetime
	}

	client.UpdatedAt = time.Now()

	// Update in database
	query := `
		UPDATE oauth_clients
		SET name = $2, description = $3, redirect_uris = $4,
		    grant_types = $5, scopes = $6, client_authentication = $7,
		    pkce_required = $8, access_token_lifetime = $9,
		    refresh_token_lifetime = $10, updated_at = $11
		WHERE id = $1
	`

	_, err = r.db.Pool.Exec(ctx, query,
		client.ID, client.Name, client.Description, client.RedirectURIs,
		client.GrantTypes, client.Scopes, client.ClientAuthentication,
		client.PKCERequired, client.AccessTokenLifetime,
		client.RefreshTokenLifetime, client.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to update OAuth client", zap.Error(err))
		return nil, commonerrors.DatabaseError("update oauth_client", err)
	}

	r.logger.Info("Updated OAuth client",
		zap.String("client_id", client.ClientID),
		zap.String("name", client.Name))

	return client, nil
}

// Delete deletes an OAuth client
func (r *ClientRepository) Delete(ctx context.Context, id string) error {
	// Check if client exists
	_, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete from database
	query := `DELETE FROM oauth_clients WHERE id = $1`
	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to delete OAuth client", zap.Error(err))
		return commonerrors.DatabaseError("delete oauth_client", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return commonerrors.NotFound("OAuth client").WithMetadata("id", id)
	}

	r.logger.Info("Deleted OAuth client", zap.String("id", id))
	return nil
}

// RegenerateSecret generates a new client secret for an existing client
func (r *ClientRepository) RegenerateSecret(ctx context.Context, id string) (string, error) {
	client, err := r.GetByID(ctx, id)
	if err != nil {
		return "", err
	}

	// Generate new secret
	clientSecret := generateClientSecret()
	secretHash := hashClientSecret(clientSecret)

	client.ClientSecretHash = secretHash
	client.UpdatedAt = time.Now()

	// Update in database
	query := `UPDATE oauth_clients SET client_secret_hash = $2, updated_at = $3 WHERE id = $1`
	_, err = r.db.Pool.Exec(ctx, query, client.ID, client.ClientSecretHash, client.UpdatedAt)
	if err != nil {
		r.logger.Error("Failed to regenerate client secret", zap.Error(err))
		return "", commonerrors.DatabaseError("update client_secret", err)
	}

	r.logger.Info("Regenerated client secret", zap.String("client_id", client.ClientID))

	return clientSecret, nil
}

// AuthenticateClient validates client credentials
// Supports both client_secret_basic (HTTP Basic) and client_secret_post (form parameters)
func (r *ClientRepository) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := r.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClientCredentials
	}

	// For public clients (no secret required)
	if client.ClientAuthentication == "none" {
		return client, nil
	}

	// Verify the client secret using constant-time comparison
	secretHash := hashClientSecret(clientSecret)
	if subtle.ConstantTimeCompare([]byte(secretHash), []byte(client.ClientSecretHash)) != 1 {
		return nil, ErrInvalidClientCredentials
	}

	return client, nil
}

// ValidateRedirectURI checks if a redirect URI is registered for the client
func (r *ClientRepository) ValidateRedirectURI(client *Client, redirectURI string) bool {
	for _, registeredURI := range client.RedirectURIs {
		if registeredURI == redirectURI {
			return true
		}
		// Support for wildcard subdomains (e.g., https://*.example.com)
		if strings.HasPrefix(registeredURI, "https://*.") {
			wildcardDomain := strings.TrimPrefix(registeredURI, "https://*.")
			if strings.HasSuffix(redirectURI, wildcardDomain) && strings.HasPrefix(redirectURI, "https://") {
				return true
			}
		}
	}
	return false
}

// ValidateGrantType checks if the client supports a specific grant type
func (r *ClientRepository) ValidateGrantType(client *Client, grantType string) bool {
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// ValidateScope checks if the requested scopes are allowed for the client
func (r *ClientRepository) ValidateScope(client *Client, scope string) bool {
	if scope == "" {
		return true
	}

	requestedScopes := strings.Split(scope, " ")
	for _, requested := range requestedScopes {
		if requested == "" {
			continue
		}
		allowed := false
		for _, allowedScope := range client.Scopes {
			if allowedScope == requested {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

// Helper functions

// generateClientID generates a unique client ID
func generateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateClientSecret generates a cryptographically random client secret
func generateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashClientSecret creates a SHA-256 hash of the client secret
func hashClientSecret(secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// generateUUID generates a UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	// Set version and variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// EnsureClientsTable creates the oauth_clients table if it doesn't exist
func (r *ClientRepository) EnsureClientsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS oauth_clients (
			id UUID PRIMARY KEY,
			client_id VARCHAR(255) UNIQUE NOT NULL,
			client_secret_hash VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
			redirect_uris TEXT[] NOT NULL,
			grant_types TEXT[] NOT NULL DEFAULT '{"authorization_code", "refresh_token"}',
			scopes TEXT[] NOT NULL DEFAULT '{"openid", "profile"}',
			client_authentication VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
			pkce_required BOOLEAN NOT NULL DEFAULT false,
			access_token_lifetime INTEGER NOT NULL DEFAULT 3600,
			refresh_token_lifetime INTEGER NOT NULL DEFAULT 2592000,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
		CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant_id ON oauth_clients(tenant_id);
	`

	_, err := r.db.Pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create oauth_clients table: %w", err)
	}

	return nil
}
