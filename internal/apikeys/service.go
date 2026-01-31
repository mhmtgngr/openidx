// Package apikeys provides API key and service account management for OpenIDX
package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// ServiceAccount represents a non-human identity used for programmatic access
type ServiceAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OwnerID     *string   `json:"owner_id,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// APIKey represents an API key record (the plaintext key is never stored)
type APIKey struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	KeyPrefix        string     `json:"key_prefix"`
	UserID           *string    `json:"user_id,omitempty"`
	ServiceAccountID *string    `json:"service_account_id,omitempty"`
	Scopes           []string   `json:"scopes"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
}

// APIKeyInfo contains the validated identity behind an API key
type APIKeyInfo struct {
	KeyID            string   `json:"key_id"`
	UserID           string   `json:"user_id"`
	ServiceAccountID string   `json:"service_account_id"`
	Scopes           []string `json:"scopes"`
	Status           string   `json:"status"`
}

// Service manages API keys and service accounts
type Service struct {
	db     *database.PostgresDB
	redis  *database.RedisClient
	logger *zap.Logger
}

// NewService creates a new API keys service
func NewService(db *database.PostgresDB, redis *database.RedisClient, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

// ---------------------------------------------------------------------------
// Service Accounts
// ---------------------------------------------------------------------------

// CreateServiceAccount creates a new service account
func (s *Service) CreateServiceAccount(ctx context.Context, name, description, ownerID string) (*ServiceAccount, error) {
	id := uuid.New().String()
	now := time.Now().UTC()

	var ownerParam interface{} = ownerID
	if ownerID == "" {
		ownerParam = nil
	}

	_, err := s.db.Pool.Exec(ctx,
		`INSERT INTO service_accounts (id, name, description, owner_id, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, name, description, ownerParam, "active", now, now,
	)
	if err != nil {
		s.logger.Error("failed to create service account", zap.Error(err))
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}

	var ownerPtr *string
	if ownerID != "" {
		ownerPtr = &ownerID
	}

	return &ServiceAccount{
		ID:          id,
		Name:        name,
		Description: description,
		OwnerID:     ownerPtr,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// ListServiceAccounts returns a paginated list of service accounts
func (s *Service) ListServiceAccounts(ctx context.Context, limit, offset int) ([]ServiceAccount, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM service_accounts`).Scan(&total)
	if err != nil {
		s.logger.Error("failed to count service accounts", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to count service accounts: %w", err)
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, name, description, owner_id, status, created_at, updated_at
		 FROM service_accounts
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		s.logger.Error("failed to list service accounts", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to list service accounts: %w", err)
	}
	defer rows.Close()

	accounts, err := scanServiceAccounts(rows)
	if err != nil {
		return nil, 0, err
	}

	return accounts, total, nil
}

// GetServiceAccount retrieves a service account by ID
func (s *Service) GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error) {
	var sa ServiceAccount
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, owner_id, status, created_at, updated_at
		 FROM service_accounts WHERE id = $1`,
		id,
	).Scan(&sa.ID, &sa.Name, &sa.Description, &sa.OwnerID, &sa.Status, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("service account not found")
		}
		s.logger.Error("failed to get service account", zap.Error(err))
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}

	return &sa, nil
}

// DeleteServiceAccount removes a service account and its associated API keys
func (s *Service) DeleteServiceAccount(ctx context.Context, id string) error {
	// Fetch key hashes before deletion so we can clear the Redis cache
	rows, err := s.db.Pool.Query(ctx,
		`SELECT key_hash FROM api_keys WHERE service_account_id = $1`,
		id,
	)
	if err != nil {
		s.logger.Error("failed to query api keys for service account", zap.Error(err))
		return fmt.Errorf("failed to delete service account: %w", err)
	}

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan key hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	rows.Close()

	// Delete the service account; api_keys rows should cascade
	tag, err := s.db.Pool.Exec(ctx,
		`DELETE FROM service_accounts WHERE id = $1`, id,
	)
	if err != nil {
		s.logger.Error("failed to delete service account", zap.Error(err))
		return fmt.Errorf("failed to delete service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}

	// Clear Redis cache for all associated keys
	for _, h := range hashes {
		s.redis.Client.Del(ctx, "apikey:"+h)
	}

	return nil
}

// ---------------------------------------------------------------------------
// API Keys
// ---------------------------------------------------------------------------

// CreateAPIKey generates a new API key, stores its hash, and returns the
// plaintext key exactly once.
func (s *Service) CreateAPIKey(ctx context.Context, name string, userID, serviceAccountID *string, scopes []string, expiresAt *time.Time) (string, *APIKey, error) {
	// Generate 32 random bytes and encode as hex (64 hex chars)
	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	plaintext := "oidx_" + hex.EncodeToString(randBytes)
	keyPrefix := plaintext[:12] // "oidx_" + first 7 hex chars

	hash := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(hash[:])

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err := s.db.Pool.Exec(ctx,
		`INSERT INTO api_keys (id, name, key_prefix, key_hash, user_id, service_account_id, scopes, expires_at, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, name, keyPrefix, keyHash, userID, serviceAccountID, scopes, expiresAt, "active", now,
	)
	if err != nil {
		s.logger.Error("failed to create api key", zap.Error(err))
		return "", nil, fmt.Errorf("failed to create api key: %w", err)
	}

	apiKey := &APIKey{
		ID:               id,
		Name:             name,
		KeyPrefix:        keyPrefix,
		UserID:           userID,
		ServiceAccountID: serviceAccountID,
		Scopes:           scopes,
		ExpiresAt:        expiresAt,
		Status:           "active",
		CreatedAt:        now,
	}

	return plaintext, apiKey, nil
}

// ValidateAPIKey checks a raw API key string against stored hashes and returns
// the associated identity information. Results are cached in Redis for 1 hour.
func (s *Service) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKeyInfo, error) {
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	cacheKey := "apikey:" + keyHash

	// Check Redis cache first
	cached, err := s.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil && cached != "" {
		var info APIKeyInfo
		if jsonErr := json.Unmarshal([]byte(cached), &info); jsonErr == nil {
			// Fire-and-forget: update last_used_at
			go s.updateLastUsed(keyHash)
			return &info, nil
		}
	}

	// Cache miss -- query the database
	var (
		keyID            string
		userID           *string
		serviceAccountID *string
		scopes           []string
		status           string
		expiresAt        *time.Time
	)

	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, service_account_id, scopes, status, expires_at
		 FROM api_keys WHERE key_hash = $1`,
		keyHash,
	).Scan(&keyID, &userID, &serviceAccountID, &scopes, &status, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("invalid api key")
		}
		s.logger.Error("failed to validate api key", zap.Error(err))
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	if status != "active" {
		return nil, fmt.Errorf("api key is %s", status)
	}

	if expiresAt != nil && expiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("api key has expired")
	}

	info := &APIKeyInfo{
		KeyID:  keyID,
		Status: status,
		Scopes: scopes,
	}
	if userID != nil {
		info.UserID = *userID
	}
	if serviceAccountID != nil {
		info.ServiceAccountID = *serviceAccountID
	}

	// Cache the result in Redis with 1 hour TTL
	if data, jsonErr := json.Marshal(info); jsonErr == nil {
		s.redis.Client.Set(ctx, cacheKey, string(data), time.Hour)
	}

	// Fire-and-forget: update last_used_at
	go s.updateLastUsed(keyHash)

	return info, nil
}

// ListAPIKeys returns all API keys for a given owner (user or service account)
func (s *Service) ListAPIKeys(ctx context.Context, ownerID string, ownerType string) ([]APIKey, error) {
	var query string
	switch strings.ToLower(ownerType) {
	case "user":
		query = `SELECT id, name, key_prefix, user_id, service_account_id, scopes, expires_at, last_used_at, status, created_at
				 FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`
	case "service_account":
		query = `SELECT id, name, key_prefix, user_id, service_account_id, scopes, expires_at, last_used_at, status, created_at
				 FROM api_keys WHERE service_account_id = $1 ORDER BY created_at DESC`
	default:
		return nil, fmt.Errorf("invalid owner type: %s (expected 'user' or 'service_account')", ownerType)
	}

	rows, err := s.db.Pool.Query(ctx, query, ownerID)
	if err != nil {
		s.logger.Error("failed to list api keys", zap.Error(err))
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	defer rows.Close()

	return scanAPIKeys(rows)
}

// RevokeAPIKey marks a single API key as revoked and clears its cache
func (s *Service) RevokeAPIKey(ctx context.Context, keyID string) error {
	var keyHash string
	err := s.db.Pool.QueryRow(ctx,
		`UPDATE api_keys SET status = 'revoked' WHERE id = $1 RETURNING key_hash`,
		keyID,
	).Scan(&keyHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("api key not found")
		}
		s.logger.Error("failed to revoke api key", zap.Error(err))
		return fmt.Errorf("failed to revoke api key: %w", err)
	}

	s.redis.Client.Del(ctx, "apikey:"+keyHash)
	return nil
}

// RevokeAllUserKeys revokes every API key owned by a user and clears the
// corresponding Redis caches
func (s *Service) RevokeAllUserKeys(ctx context.Context, userID string) error {
	rows, err := s.db.Pool.Query(ctx,
		`UPDATE api_keys SET status = 'revoked' WHERE user_id = $1 AND status = 'active' RETURNING key_hash`,
		userID,
	)
	if err != nil {
		s.logger.Error("failed to revoke all user keys", zap.Error(err))
		return fmt.Errorf("failed to revoke all user keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var keyHash string
		if err := rows.Scan(&keyHash); err != nil {
			s.logger.Error("failed to scan key hash during revocation", zap.Error(err))
			continue
		}
		s.redis.Client.Del(ctx, "apikey:"+keyHash)
	}

	return rows.Err()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// updateLastUsed sets the last_used_at timestamp for a key identified by its
// hash. It uses a background context so the caller is not blocked.
func (s *Service) updateLastUsed(keyHash string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.Pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = $1 WHERE key_hash = $2`,
		time.Now().UTC(), keyHash,
	)
	if err != nil {
		s.logger.Warn("failed to update last_used_at", zap.Error(err))
	}
}

// scanServiceAccounts reads all rows into a slice of ServiceAccount
func scanServiceAccounts(rows pgx.Rows) ([]ServiceAccount, error) {
	var accounts []ServiceAccount
	for rows.Next() {
		var sa ServiceAccount
		if err := rows.Scan(&sa.ID, &sa.Name, &sa.Description, &sa.OwnerID, &sa.Status, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan service account: %w", err)
		}
		accounts = append(accounts, sa)
	}
	return accounts, rows.Err()
}

// scanAPIKeys reads all rows into a slice of APIKey
func scanAPIKeys(rows pgx.Rows) ([]APIKey, error) {
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyPrefix,
			&k.UserID, &k.ServiceAccountID,
			&k.Scopes,
			&k.ExpiresAt, &k.LastUsedAt,
			&k.Status, &k.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
