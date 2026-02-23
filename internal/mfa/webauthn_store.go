// Package mfa provides WebAuthn/FIDO2 credential storage for OpenIDX
package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// WebAuthnStore defines the interface for WebAuthn credential storage
type WebAuthnStore interface {
	// Credential operations
	CreateCredential(ctx context.Context, cred *WebAuthnCredential) error
	GetCredential(ctx context.Context, id uuid.UUID) (*WebAuthnCredential, error)
	GetCredentialByID(ctx context.Context, credentialID string) (*WebAuthnCredential, error)
	ListCredentials(ctx context.Context, userID uuid.UUID) ([]*WebAuthnCredential, error)
	UpdateCredential(ctx context.Context, cred *WebAuthnCredential) error
	DeleteCredential(ctx context.Context, id uuid.UUID) error
	DeleteCredentialByCredentialID(ctx context.Context, credentialID string, userID uuid.UUID) error

	// User operations
	GetUser(ctx context.Context, userID uuid.UUID) (*User, error)

	// Session operations (for storing WebAuthn session data)
	StoreSession(ctx context.Context, key string, data interface{}, ttl time.Duration) error
	GetSession(ctx context.Context, key string) ([]byte, error)
	DeleteSession(ctx context.Context, key string) error

	// Health check
	Ping(ctx context.Context) error
}

// PostgreSQLWebAuthnStore implements WebAuthnStore using PostgreSQL
type PostgreSQLWebAuthnStore struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

// NewPostgreSQLWebAuthnStore creates a new PostgreSQL WebAuthn store
func NewPostgreSQLWebAuthnStore(pool *pgxpool.Pool, logger *zap.Logger) *PostgreSQLWebAuthnStore {
	return &PostgreSQLWebAuthnStore{
		pool:   pool,
		logger: logger,
	}
}

// CreateCredential stores a new WebAuthn credential
func (s *PostgreSQLWebAuthnStore) CreateCredential(ctx context.Context, cred *WebAuthnCredential) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal transports to JSON
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("marshal transports: %w", err)
	}

	query := `
		INSERT INTO webauthn_credentials (
			id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, user_id, user_handle, friendly_name,
			backup_eligible, backup_state, created_at, last_used_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = s.pool.Exec(ctx, query,
		cred.ID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AttestationType,
		cred.AAGUID,
		cred.SignCount,
		transportsJSON,
		cred.UserID,
		cred.UserHandle,
		cred.FriendlyName,
		cred.BackupEligible,
		cred.BackupState,
		cred.CreatedAt,
		cred.LastUsedAt,
	)

	if err != nil {
		return fmt.Errorf("insert credential: %w", err)
	}

	s.logger.Info("Created WebAuthn credential",
		zap.String("user_id", cred.UserID.String()),
		zap.String("credential_id", cred.CredentialID),
		zap.String("friendly_name", cred.FriendlyName),
	)

	return nil
}

// GetCredential retrieves a credential by its database ID
func (s *PostgreSQLWebAuthnStore) GetCredential(ctx context.Context, id uuid.UUID) (*WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, user_id, user_handle, friendly_name,
			backup_eligible, backup_state, created_at, last_used_at
		FROM webauthn_credentials
		WHERE id = $1
	`

	return s.scanCredential(s.pool.QueryRow(ctx, query, id))
}

// GetCredentialByID retrieves a credential by its WebAuthn credential ID
func (s *PostgreSQLWebAuthnStore) GetCredentialByID(ctx context.Context, credentialID string) (*WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, user_id, user_handle, friendly_name,
			backup_eligible, backup_state, created_at, last_used_at
		FROM webauthn_credentials
		WHERE credential_id = $1
	`

	return s.scanCredential(s.pool.QueryRow(ctx, query, credentialID))
}

// ListCredentials retrieves all credentials for a user
func (s *PostgreSQLWebAuthnStore) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, user_id, user_handle, friendly_name,
			backup_eligible, backup_state, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*WebAuthnCredential
	for rows.Next() {
		cred, err := s.scanCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return credentials, nil
}

// UpdateCredential updates an existing credential
func (s *PostgreSQLWebAuthnStore) UpdateCredential(ctx context.Context, cred *WebAuthnCredential) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal transports to JSON
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("marshal transports: %w", err)
	}

	query := `
		UPDATE webauthn_credentials SET
			public_key = $2,
			sign_count = $3,
			transports = $4,
			friendly_name = $5,
			backup_eligible = $6,
			backup_state = $7,
			last_used_at = $8
		WHERE id = $1
	`

	result, err := s.pool.Exec(ctx, query,
		cred.ID,
		cred.PublicKey,
		cred.SignCount,
		transportsJSON,
		cred.FriendlyName,
		cred.BackupEligible,
		cred.BackupState,
		cred.LastUsedAt,
	)

	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("credential not found: %s", cred.ID.String())
	}

	s.logger.Info("Updated WebAuthn credential",
		zap.String("credential_id", cred.CredentialID),
		zap.Uint32("sign_count", cred.SignCount),
	)

	return nil
}

// DeleteCredential deletes a credential by its database ID
func (s *PostgreSQLWebAuthnStore) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `DELETE FROM webauthn_credentials WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("credential not found: %s", id.String())
	}

	s.logger.Info("Deleted WebAuthn credential",
		zap.String("id", id.String()),
	)

	return nil
}

// DeleteCredentialByCredentialID deletes a credential by its WebAuthn credential ID for a specific user
func (s *PostgreSQLWebAuthnStore) DeleteCredentialByCredentialID(ctx context.Context, credentialID string, userID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `DELETE FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2`

	result, err := s.pool.Exec(ctx, query, credentialID, userID)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("credential not found: %s", credentialID)
	}

	s.logger.Info("Deleted WebAuthn credential",
		zap.String("credential_id", credentialID),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// GetUser retrieves a user by ID
// This assumes the users table exists and has at least these columns
func (s *PostgreSQLWebAuthnStore) GetUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Try to get user from users table
	query := `
		SELECT id, username, display_name
		FROM users
		WHERE id = $1
	`

	var user User
	err := s.pool.QueryRow(ctx, query, userID).Scan(
		&user.UserID,
		&user.Username,
		&user.DisplayName,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Try alternative table name or create a minimal user object
			// This allows WebAuthn to work even without a full users table
			return &User{
				UserID:      userID,
				Username:    userID.String(),
				DisplayName: "User",
			}, nil
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	return &user, nil
}

// StoreSession stores session data with an expiration time
// This uses the webauthn_sessions table for storing WebAuthn session data
func (s *PostgreSQLWebAuthnStore) StoreSession(ctx context.Context, key string, data interface{}, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Marshal data to JSON
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal session data: %w", err)
	}

	expiresAt := time.Now().Add(ttl)

	query := `
		INSERT INTO webauthn_sessions (session_key, session_data, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (session_key) DO UPDATE SET
			session_data = EXCLUDED.session_data,
			expires_at = EXCLUDED.expires_at
	`

	_, err = s.pool.Exec(ctx, query, key, dataJSON, expiresAt)
	if err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	return nil
}

// GetSession retrieves session data by key
func (s *PostgreSQLWebAuthnStore) GetSession(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT session_data
		FROM webauthn_sessions
		WHERE session_key = $1 AND expires_at > NOW()
	`

	var dataJSON []byte
	err := s.pool.QueryRow(ctx, query, key).Scan(&dataJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	return dataJSON, nil
}

// DeleteSession deletes a session by key
func (s *PostgreSQLWebAuthnStore) DeleteSession(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `DELETE FROM webauthn_sessions WHERE session_key = $1`

	_, err := s.pool.Exec(ctx, query, key)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// Ping checks if the database connection is alive
func (s *PostgreSQLWebAuthnStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// CleanExpiredSessions removes expired session data
// Should be called periodically (e.g., via a cron job)
func (s *PostgreSQLWebAuthnStore) CleanExpiredSessions(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `DELETE FROM webauthn_sessions WHERE expires_at <= NOW()`

	result, err := s.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("clean expired sessions: %w", err)
	}

	s.logger.Info("Cleaned expired WebAuthn sessions",
		zap.Int64("count", result.RowsAffected()),
	)

	return nil
}

// scanCredential scans a WebAuthnCredential from a database row
func (s *PostgreSQLWebAuthnStore) scanCredential(row pgx.Row) (*WebAuthnCredential, error) {
	var cred WebAuthnCredential
	var transportsJSON []byte

	err := row.Scan(
		&cred.ID,
		&cred.CredentialID,
		&cred.PublicKey,
		&cred.AttestationType,
		&cred.AAGUID,
		&cred.SignCount,
		&transportsJSON,
		&cred.UserID,
		&cred.UserHandle,
		&cred.FriendlyName,
		&cred.BackupEligible,
		&cred.BackupState,
		&cred.CreatedAt,
		&cred.LastUsedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("credential not found")
		}
		return nil, fmt.Errorf("scan credential: %w", err)
	}

	// Unmarshal transports
	if len(transportsJSON) > 0 {
		if err := json.Unmarshal(transportsJSON, &cred.Transports); err != nil {
			return nil, fmt.Errorf("unmarshal transports: %w", err)
		}
	}

	return &cred, nil
}

// InMemoryWebAuthnStore is an in-memory implementation for testing
type InMemoryWebAuthnStore struct {
	credentials map[uuid.UUID]*WebAuthnCredential
	byID        map[string]*WebAuthnCredential
	byUser      map[uuid.UUID][]*WebAuthnCredential
	sessions    map[string][]byte
	users       map[uuid.UUID]*User
	logger      *zap.Logger
}

// NewInMemoryWebAuthnStore creates a new in-memory WebAuthn store
func NewInMemoryWebAuthnStore(logger *zap.Logger) *InMemoryWebAuthnStore {
	return &InMemoryWebAuthnStore{
		credentials: make(map[uuid.UUID]*WebAuthnCredential),
		byID:        make(map[string]*WebAuthnCredential),
		byUser:      make(map[uuid.UUID][]*WebAuthnCredential),
		sessions:    make(map[string][]byte),
		users:       make(map[uuid.UUID]*User),
		logger:      logger,
	}
}

// CreateCredential stores a new credential
func (s *InMemoryWebAuthnStore) CreateCredential(ctx context.Context, cred *WebAuthnCredential) error {
	s.credentials[cred.ID] = cred
	s.byID[cred.CredentialID] = cred
	s.byUser[cred.UserID] = append(s.byUser[cred.UserID], cred)

	if s.logger != nil {
		s.logger.Info("Created in-memory credential",
			zap.String("credential_id", cred.CredentialID),
		)
	}

	return nil
}

// GetCredential retrieves a credential by database ID
func (s *InMemoryWebAuthnStore) GetCredential(ctx context.Context, id uuid.UUID) (*WebAuthnCredential, error) {
	cred, ok := s.credentials[id]
	if !ok {
		return nil, fmt.Errorf("credential not found")
	}
	return cred, nil
}

// GetCredentialByID retrieves a credential by WebAuthn credential ID
func (s *InMemoryWebAuthnStore) GetCredentialByID(ctx context.Context, credentialID string) (*WebAuthnCredential, error) {
	cred, ok := s.byID[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential not found")
	}
	return cred, nil
}

// ListCredentials retrieves all credentials for a user
func (s *InMemoryWebAuthnStore) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*WebAuthnCredential, error) {
	creds, ok := s.byUser[userID]
	if !ok {
		return []*WebAuthnCredential{}, nil
	}
	return creds, nil
}

// UpdateCredential updates an existing credential
func (s *InMemoryWebAuthnStore) UpdateCredential(ctx context.Context, cred *WebAuthnCredential) error {
	s.credentials[cred.ID] = cred
	s.byID[cred.CredentialID] = cred

	// Update in user list
	for i, c := range s.byUser[cred.UserID] {
		if c.ID == cred.ID {
			s.byUser[cred.UserID][i] = cred
			break
		}
	}

	return nil
}

// DeleteCredential deletes a credential
func (s *InMemoryWebAuthnStore) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	cred, ok := s.credentials[id]
	if !ok {
		return fmt.Errorf("credential not found")
	}

	delete(s.credentials, id)
	delete(s.byID, cred.CredentialID)

	// Remove from user list
	creds := s.byUser[cred.UserID]
	for i, c := range creds {
		if c.ID == id {
			s.byUser[cred.UserID] = append(creds[:i], creds[i+1:]...)
			break
		}
	}

	return nil
}

// DeleteCredentialByCredentialID deletes a credential by WebAuthn ID
func (s *InMemoryWebAuthnStore) DeleteCredentialByCredentialID(ctx context.Context, credentialID string, userID uuid.UUID) error {
	cred, ok := s.byID[credentialID]
	if !ok {
		return fmt.Errorf("credential not found")
	}

	if cred.UserID != userID {
		return fmt.Errorf("credential belongs to different user")
	}

	return s.DeleteCredential(ctx, cred.ID)
}

// GetUser retrieves a user
func (s *InMemoryWebAuthnStore) GetUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	user, ok := s.users[userID]
	if !ok {
		// Return a default user if not found
		return &User{
			UserID:      userID,
			Username:    userID.String(),
			DisplayName: "Test User",
		}, nil
	}
	return user, nil
}

// SetUser sets a user in the in-memory store
func (s *InMemoryWebAuthnStore) SetUser(user *User) {
	s.users[user.UserID] = user
}

// StoreSession stores session data
func (s *InMemoryWebAuthnStore) StoreSession(ctx context.Context, key string, data interface{}, ttl time.Duration) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}
	s.sessions[key] = dataJSON
	return nil
}

// GetSession retrieves session data
func (s *InMemoryWebAuthnStore) GetSession(ctx context.Context, key string) ([]byte, error) {
	data, ok := s.sessions[key]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return data, nil
}

// DeleteSession deletes a session
func (s *InMemoryWebAuthnStore) DeleteSession(ctx context.Context, key string) error {
	delete(s.sessions, key)
	return nil
}

// Ping checks the store
func (s *InMemoryWebAuthnStore) Ping(ctx context.Context) error {
	return nil
}
