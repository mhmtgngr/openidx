// Package oauth — OAuth client data-access layer.
//
// OAuthClientStore is the first aggregate extracted from the oauth service with
// the Repository pattern (the same shape proven in the identity service — see
// docs/architecture/design-patterns-review.md). It shows the pattern generalizes
// across services: SQL isolated in one type, tenant-scoped, primary-vs-replica
// chosen per query.
//
// Pool choice:
//   - GetByClientID reads the PRIMARY. Client lookup gates every token grant and
//     validates the client secret; a just-rotated secret or a just-disabled
//     client must be seen immediately (read-after-write), so we do not risk
//     replica lag on this security-critical path.
//   - List reads the replica (admin/dashboard, lag-tolerant).
//   - Create/Update/Delete are writes → primary.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrOAuthClientNotFound is the sentinel for an OAuth client miss within the tenant.
var ErrOAuthClientNotFound = errors.New("oauth client not found")

// OAuthClientStore is the data-access port for OAuth clients.
type OAuthClientStore interface {
	// GetByClientID returns the full client (incl. secret) by client_id in the
	// tenant, or ErrOAuthClientNotFound. Reads the PRIMARY (security-critical).
	GetByClientID(ctx context.Context, clientID string) (*OAuthClient, error)

	// List returns a page of clients (summary fields) plus the total count.
	// Reads the replica (lag-tolerant).
	List(ctx context.Context, offset, limit int) ([]OAuthClient, int, error)

	// Create inserts a client (primary).
	Create(ctx context.Context, client *OAuthClient) error

	// Update mutates a client by client_id (primary). Returns ErrOAuthClientNotFound
	// when no row matches.
	Update(ctx context.Context, clientID string, client *OAuthClient) error

	// Delete removes a client by client_id (primary). Idempotent.
	Delete(ctx context.Context, clientID string) error
}

// PostgresOAuthClientStore is the pgx implementation of OAuthClientStore.
type PostgresOAuthClientStore struct {
	db           *database.PostgresDB
	queryTimeout time.Duration
}

// NewPostgresOAuthClientStore constructs the pgx-backed client repository. The
// timeout bounds each query (mirrors the service's withDBTimeout).
func NewPostgresOAuthClientStore(db *database.PostgresDB) *PostgresOAuthClientStore {
	return &PostgresOAuthClientStore{db: db, queryTimeout: 5 * time.Second}
}

func (r *PostgresOAuthClientStore) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.queryTimeout)
}

// GetByClientID implements OAuthClientStore. Reads the PRIMARY on purpose.
func (r *PostgresOAuthClientStore) GetByClientID(ctx context.Context, clientID string) (*OAuthClient, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	var client OAuthClient
	var clientSecret, description, logoURI, policyURI, tosURI *string
	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON []byte

	err = r.db.Pool.QueryRow(dbCtx, `
		SELECT id, client_id, client_secret, name, description, type,
		       redirect_uris, grant_types, response_types, scopes,
		       logo_uri, policy_uri, tos_uri, pkce_required,
		       allow_refresh_token, access_token_lifetime, refresh_token_lifetime,
		       created_at, updated_at
		FROM oauth_clients WHERE client_id = $1 AND org_id = $2
	`, clientID, org.ID).Scan(
		&client.ID, &client.ClientID, &clientSecret, &client.Name, &description,
		&client.Type, &redirectURIsJSON, &grantTypesJSON, &responseTypesJSON, &scopesJSON,
		&logoURI, &policyURI, &tosURI, &client.PKCERequired,
		&client.AllowRefreshToken, &client.AccessTokenLifetime, &client.RefreshTokenLifetime,
		&client.CreatedAt, &client.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("get oauth client: %w", err)
	}

	if clientSecret != nil {
		client.ClientSecret = *clientSecret
	}
	if description != nil {
		client.Description = *description
	}
	if logoURI != nil {
		client.LogoURI = *logoURI
	}
	if policyURI != nil {
		client.PolicyURI = *policyURI
	}
	if tosURI != nil {
		client.TOSUri = *tosURI
	}
	json.Unmarshal(redirectURIsJSON, &client.RedirectURIs)
	json.Unmarshal(grantTypesJSON, &client.GrantTypes)
	json.Unmarshal(responseTypesJSON, &client.ResponseTypes)
	json.Unmarshal(scopesJSON, &client.Scopes)

	return &client, nil
}

// List implements OAuthClientStore. Reads the replica.
func (r *PostgresOAuthClientStore) List(ctx context.Context, offset, limit int) ([]OAuthClient, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}
	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	var total int
	if err := r.db.Reader().QueryRow(dbCtx,
		"SELECT COUNT(*) FROM oauth_clients WHERE org_id = $1", org.ID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count oauth clients: %w", err)
	}

	rows, err := r.db.Reader().Query(dbCtx, `
		SELECT id, client_id, name, description, type, created_at, updated_at
		FROM oauth_clients
		WHERE org_id = $3
		ORDER BY created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit, org.ID)
	if err != nil {
		return nil, 0, fmt.Errorf("list oauth clients: %w", err)
	}
	defer rows.Close()

	var clients []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var desc *string
		if err := rows.Scan(&c.ID, &c.ClientID, &c.Name, &desc, &c.Type, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan oauth client: %w", err)
		}
		if desc != nil {
			c.Description = *desc
		}
		clients = append(clients, c)
	}
	return clients, total, rows.Err()
}

// Create implements OAuthClientStore. WRITE — primary.
func (r *PostgresOAuthClientStore) Create(ctx context.Context, client *OAuthClient) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now
	if client.AccessTokenLifetime == 0 {
		client.AccessTokenLifetime = 3600
	}
	if client.RefreshTokenLifetime == 0 {
		client.RefreshTokenLifetime = 86400
	}

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)

	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	_, err = r.db.Pool.Exec(dbCtx, `
		INSERT INTO oauth_clients (
			id, client_id, client_secret, name, description, type,
			redirect_uris, grant_types, response_types, scopes,
			logo_uri, policy_uri, tos_uri, pkce_required,
			allow_refresh_token, access_token_lifetime, refresh_token_lifetime,
			created_at, updated_at, org_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`, client.ID, client.ClientID, client.ClientSecret, client.Name, client.Description,
		client.Type, redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON,
		client.LogoURI, client.PolicyURI, client.TOSUri, client.PKCERequired,
		client.AllowRefreshToken, client.AccessTokenLifetime, client.RefreshTokenLifetime,
		client.CreatedAt, client.UpdatedAt, org.ID)
	if err != nil {
		return fmt.Errorf("create oauth client: %w", err)
	}
	return nil
}

// Update implements OAuthClientStore. WRITE — primary.
func (r *PostgresOAuthClientStore) Update(ctx context.Context, clientID string, client *OAuthClient) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	client.UpdatedAt = now

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)

	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	result, err := r.db.Pool.Exec(dbCtx, `
		UPDATE oauth_clients
		SET name = $2, description = $3, redirect_uris = $4, grant_types = $5,
		    response_types = $6, scopes = $7, pkce_required = $8,
		    allow_refresh_token = $9, access_token_lifetime = $10,
		    refresh_token_lifetime = $11, updated_at = $12
		WHERE client_id = $1 AND org_id = $13
	`, clientID, client.Name, client.Description, redirectURIsJSON, grantTypesJSON,
		responseTypesJSON, scopesJSON, client.PKCERequired, client.AllowRefreshToken,
		client.AccessTokenLifetime, client.RefreshTokenLifetime, now, org.ID)
	if err != nil {
		return fmt.Errorf("update oauth client: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrOAuthClientNotFound
	}
	return nil
}

// Delete implements OAuthClientStore. WRITE — primary. Idempotent.
func (r *PostgresOAuthClientStore) Delete(ctx context.Context, clientID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()
	if _, err := r.db.Pool.Exec(dbCtx,
		`DELETE FROM oauth_clients WHERE client_id = $1 AND org_id = $2`, clientID, org.ID); err != nil {
		return fmt.Errorf("delete oauth client: %w", err)
	}
	return nil
}

// Ensure the concrete type satisfies the interface at compile time.
var _ OAuthClientStore = (*PostgresOAuthClientStore)(nil)
