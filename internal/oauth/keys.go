// Package oauth provides RSA key management and JWKS endpoint functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

var (
	// ErrKeyGenerationFailed is returned when RSA key generation fails
	ErrKeyGenerationFailed = errors.New("key_generation_failed")
	// ErrKeyNotFound is returned when the requested key is not found
	ErrKeyNotFound = errors.New("key_not_found")
	// ErrKeyInvalid is returned when a key is invalid
	ErrKeyInvalid = errors.New("key_invalid")
	// ErrKeyRotationInProgress is returned when a key rotation is already in progress
	ErrKeyRotationInProgress = errors.New("key_rotation_in_progress")
)

const (
	// KeyRotationOverlap is the overlap period during which old and new keys are both valid
	// This allows for graceful key rotation without service interruption
	KeyRotationOverlap = 24 * time.Hour

	// KeySize is the RSA key size in bits
	KeySize = 2048

	// KeyLifetime is the recommended lifetime of a signing key
	KeyLifetime = 90 * 24 * time.Hour // 90 days

	// CurrentKeyID is the ID of the current active signing key
	CurrentKeyID = "openidx-key-1"
)

// KeyMetadata stores metadata about a cryptographic key
type KeyMetadata struct {
	KeyID        string    `json:"key_id" db:"key_id"`
	KeyType      string    `json:"key_type" db:"key_type"`      // RSA, EC, etc.
	Algorithm    string    `json:"algorithm" db:"algorithm"`    // RS256, RS384, RS512, etc.
	Use          string    `json:"use" db:"use"`                // sig (signature) or enc (encryption)
	PublicKey    string    `json:"public_key,omitempty" db:"public_key"`
	PrivateKey   string    `json:"-" db:"private_key"`          // Never expose in JSON
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	RotatedAt    *time.Time `json:"rotated_at,omitempty" db:"rotated_at"`
	Status       string    `json:"status" db:"status"`          // active, rotated, expired
	KeyVersion   int       `json:"key_version" db:"key_version"`
}

// JWK represents a JSON Web Key per RFC 7517
type JWK struct {
	Kty string `json:"kty"` // Key type
	Use string `json:"use"` // Public key use - "sig" or "enc"
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // Modulus (for RSA)
	E   string `json:"e"`   // Exponent (for RSA)
	Crv string `json:"crv,omitempty"` // Curve (for EC)
	X   string `json:"x,omitempty"`   // X coordinate (for EC)
	Y   string `json:"y,omitempty"`   // Y coordinate (for EC)
}

// JWKS represents a JSON Web Key Set per RFC 7517
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyManager manages RSA keys for JWT signing and verification
type KeyManager struct {
	db            *database.PostgresDB
	logger        *zap.Logger
	issuer        string
	currentKey    *rsa.PrivateKey
	currentKeyID  string
	publicKeys    map[string]*rsa.PublicKey // kid -> public key
	mu            sync.RWMutex
	rotationMutex sync.Mutex
}

// NewKeyManager creates a new key manager
func NewKeyManager(db *database.PostgresDB, logger *zap.Logger, issuer string) (*KeyManager, error) {
	km := &KeyManager{
		db:         db,
		logger:     logger.With(zap.String("component", "key_manager")),
		issuer:     issuer,
		publicKeys: make(map[string]*rsa.PublicKey),
	}

	// Try to load keys from database
	if err := km.loadKeysFromDatabase(context.Background()); err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			// No keys found, generate initial key
			if err := km.generateAndStoreInitialKey(context.Background()); err != nil {
				return nil, fmt.Errorf("failed to generate initial key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load keys from database: %w", err)
		}
	}

	return km, nil
}

// loadKeysFromDatabase loads keys from the database
func (km *KeyManager) loadKeysFromDatabase(ctx context.Context) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Get the current active key
	var keyMeta KeyMetadata
	err := km.db.Pool.QueryRow(ctx, `
		SELECT key_id, key_type, algorithm, use, public_key, private_key,
		       created_at, expires_at, rotated_at, status, key_version
		FROM oauth_signing_keys
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(
		&keyMeta.KeyID, &keyMeta.KeyType, &keyMeta.Algorithm, &keyMeta.Use,
		&keyMeta.PublicKey, &keyMeta.PrivateKey, &keyMeta.CreatedAt,
		&keyMeta.ExpiresAt, &keyMeta.RotatedAt, &keyMeta.Status, &keyMeta.KeyVersion,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("failed to query signing keys: %w", err)
	}

	// Parse the private key
	privateKey, err := km.parsePrivateKey(keyMeta.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	km.currentKey = privateKey
	km.currentKeyID = keyMeta.KeyID

	// Load all public keys (including rotated keys that are still valid)
	rows, err := km.db.Pool.Query(ctx, `
		SELECT key_id, public_key, status, expires_at
		FROM oauth_signing_keys
		WHERE (status = 'active' OR status = 'rotated')
		AND (expires_at > NOW() OR expires_at > NOW() - INTERVAL '1 day')
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("failed to query public keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var keyID, publicKeyPem, status string
		var expiresAt time.Time
		if err := rows.Scan(&keyID, &publicKeyPem, &status, &expiresAt); err != nil {
			continue
		}

		// Skip if key is expired
		if status == "rotated" && time.Now().After(expiresAt.Add(KeyRotationOverlap)) {
			continue
		}

		// Parse the public key
		publicKey, err := km.parsePublicKey(publicKeyPem)
		if err != nil {
			km.logger.Warn("Failed to parse public key",
				zap.String("key_id", keyID),
				zap.Error(err))
			continue
		}

		km.publicKeys[keyID] = publicKey
	}

	km.logger.Info("Loaded signing keys from database",
		zap.String("current_key_id", km.currentKeyID),
		zap.Int("total_public_keys", len(km.publicKeys)))

	return nil
}

// generateAndStoreInitialKey generates and stores the initial signing key
func (km *KeyManager) generateAndStoreInitialKey(ctx context.Context) error {
	km.logger.Info("Generating initial RSA signing key")

	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode keys as PEM
	privateKeyPEM := km.encodePrivateKey(privateKey)
	publicKeyPEM := km.encodePublicKey(&privateKey.PublicKey)

	// Store in database
	now := time.Now()
	expiresAt := now.Add(KeyLifetime)

	_, err = km.db.Pool.Exec(ctx, `
		INSERT INTO oauth_signing_keys (
			key_id, key_type, algorithm, use, public_key, private_key,
			created_at, expires_at, status, key_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, CurrentKeyID, "RSA", "RS256", "sig", publicKeyPEM, privateKeyPEM,
		now, expiresAt, "active", 1)

	if err != nil {
		return fmt.Errorf("failed to store signing key: %w", err)
	}

	km.mu.Lock()
	km.currentKey = privateKey
	km.currentKeyID = CurrentKeyID
	km.publicKeys[CurrentKeyID] = &privateKey.PublicKey
	km.mu.Unlock()

	km.logger.Info("Initial RSA signing key generated and stored",
		zap.String("key_id", CurrentKeyID),
		zap.Time("expires_at", expiresAt))

	return nil
}

// GetSigningKey returns the current signing key
func (km *KeyManager) GetSigningKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKey
}

// GetSigningKeyID returns the current signing key ID
func (km *KeyManager) GetSigningKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKeyID
}

// GetPublicKey returns a public key by key ID
func (km *KeyManager) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, ok := km.publicKeys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

// GetPublicKeys returns all public keys for JWKS endpoint
func (km *KeyManager) GetPublicKeys() map[string]*rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Return a copy to prevent concurrent modification
	result := make(map[string]*rsa.PublicKey, len(km.publicKeys))
	for k, v := range km.publicKeys {
		result[k] = v
	}
	return result
}

// RotateKey performs a key rotation with overlap period
// The old key remains valid for KeyRotationOverlap (24 hours)
func (km *KeyManager) RotateKey(ctx context.Context) error {
	km.rotationMutex.Lock()
	defer km.rotationMutex.Unlock()

	km.logger.Info("Starting key rotation")

	km.mu.Lock()

	// Mark current key as rotated
	oldKeyID := km.currentKeyID
	now := time.Now()

	// Mark the old key as rotated but still valid for overlap period
	_, err := km.db.Pool.Exec(ctx, `
		UPDATE oauth_signing_keys
		SET status = 'rotated', rotated_at = $1
		WHERE key_id = $2 AND status = 'active'
	`, now, oldKeyID)

	if err != nil {
		km.mu.Unlock()
		return fmt.Errorf("failed to mark old key as rotated: %w", err)
	}

	// Generate new key
	newKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		km.mu.Unlock()
		return fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	// Generate new key ID
	newKeyID := fmt.Sprintf("openidx-key-%d", time.Now().Unix())

	// Encode keys
	privateKeyPEM := km.encodePrivateKey(newKey)
	publicKeyPEM := km.encodePublicKey(&newKey.PublicKey)

	// Store new key
	expiresAt := now.Add(KeyLifetime)

	// Get the next key version
	var nextVersion int
	err = km.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(key_version), 0) + 1 FROM oauth_signing_keys
	`).Scan(&nextVersion)

	if err != nil {
		km.mu.Unlock()
		return fmt.Errorf("failed to get next key version: %w", err)
	}

	_, err = km.db.Pool.Exec(ctx, `
		INSERT INTO oauth_signing_keys (
			key_id, key_type, algorithm, use, public_key, private_key,
			created_at, expires_at, status, key_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, newKeyID, "RSA", "RS256", "sig", publicKeyPEM, privateKeyPEM,
		now, expiresAt, "active", nextVersion)

	if err != nil {
		km.mu.Unlock()
		return fmt.Errorf("failed to store new signing key: %w", err)
	}

	// Update in-memory state
	km.currentKey = newKey
	km.currentKeyID = newKeyID
	km.publicKeys[newKeyID] = &newKey.PublicKey

	km.mu.Unlock()

	km.logger.Info("Key rotation completed",
		zap.String("old_key_id", oldKeyID),
		zap.String("new_key_id", newKeyID),
		zap.Duration("overlap_period", KeyRotationOverlap))

	return nil
}

// RevokeOldKeys revokes keys that are past their overlap period
func (km *KeyManager) RevokeOldKeys(ctx context.Context) error {
	km.logger.Info("Revoking expired keys")

	// Find keys that were rotated more than overlap period ago
	cutoff := time.Now().Add(-KeyRotationOverlap)

	result, err := km.db.Pool.Exec(ctx, `
		UPDATE oauth_signing_keys
		SET status = 'expired'
		WHERE status = 'rotated'
		AND rotated_at < $1
	`, cutoff)

	if err != nil {
		return fmt.Errorf("failed to revoke old keys: %w", err)
	}

	rowsAffected := result.RowsAffected()

	// Remove from in-memory cache
	km.mu.Lock()
	// Clean up public keys for expired entries
	for keyID, pubKey := range km.publicKeys {
		if keyID != km.currentKeyID {
			delete(km.publicKeys, keyID)
			_ = pubKey // Use the variable
		}
	}
	km.mu.Unlock()

	km.logger.Info("Revoked expired keys",
		zap.Int64("count", rowsAffected),
		zap.Time("cutoff", cutoff))

	return nil
}

// ShouldRotateKey checks if the current key should be rotated
func (km *KeyManager) ShouldRotateKey() bool {
	// Get the current key's metadata from database
	var expiresAt time.Time
	err := km.db.Pool.QueryRow(context.Background(), `
		SELECT expires_at FROM oauth_signing_keys
		WHERE key_id = $1 AND status = 'active'
	`, km.currentKeyID).Scan(&expiresAt)

	if err != nil {
		return false
	}

	// Rotate if key expires within 7 days
	return time.Until(expiresAt) < 7*24*time.Hour
}

// parsePrivateKey parses a PEM-encoded private key
func (km *KeyManager) parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrKeyInvalid
	}

	// Try PKCS1 first
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Try PKCS8
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if rsaKey, ok := pkcs8Key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	return nil, ErrKeyInvalid
}

// parsePublicKey parses a PEM-encoded public key
func (km *KeyManager) parsePublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrKeyInvalid
	}

	// Try PKIX (standard for public keys)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if rsaKey, ok := pub.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}

	// Try PKCS1
	pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return pub.(*rsa.PublicKey), nil
	}

	return nil, ErrKeyInvalid
}

// encodePrivateKey encodes a private key to PEM format
func (km *KeyManager) encodePrivateKey(key *rsa.PrivateKey) string {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// encodePublicKey encodes a public key to PEM format
func (km *KeyManager) encodePublicKey(key *rsa.PublicKey) string {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		// Fallback to PKCS1
		keyBytes = x509.MarshalPKCS1PublicKey(key)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// BuildJWKS builds the JSON Web Key Set from the current public keys
func (km *KeyManager) BuildJWKS() *JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()

	jwks := &JWKS{
		Keys: make([]JWK, 0, len(km.publicKeys)),
	}

	for keyID, pubKey := range km.publicKeys {
		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: keyID,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:   km.encodeExponent(pubKey.E),
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks
}

// encodeExponent encodes the RSA exponent for JWK format
func (km *KeyManager) encodeExponent(e int) string {
	// Convert exponent to bytes
	// Most RSA keys have exponent 65537 (0x010001)
	bytes := []byte{
		byte(e >> 24),
		byte(e >> 16),
		byte(e >> 8),
		byte(e),
	}
	// Trim leading zeros
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// HandleJWKS handles the JWKS endpoint
// Implements RFC 7517 and JWK specification
func (km *KeyManager) HandleJWKS(c *gin.Context) {
	// Set CORS headers
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}

	jwks := km.BuildJWKS()
	c.JSON(http.StatusOK, jwks)
}

// ValidateJWT validates a JWT token using the JWKS
func (km *KeyManager) ValidateJWT(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			// Fall back to current key
			return &km.currentKey.PublicKey, nil
		}

		// Get public key by ID
		publicKey, err := km.GetPublicKey(keyID)
		if err != nil {
			// Key not found, try current key
			return &km.currentKey.PublicKey, nil
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}

	return nil, errors.New("invalid token")
}

// EnsureSigningKeysTable creates the oauth_signing_keys table if it doesn't exist
func (km *KeyManager) EnsureSigningKeysTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS oauth_signing_keys (
			key_id VARCHAR(255) PRIMARY KEY,
			key_type VARCHAR(50) NOT NULL,
			algorithm VARCHAR(50) NOT NULL,
			use VARCHAR(10) NOT NULL,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP NOT NULL,
			rotated_at TIMESTAMP,
			status VARCHAR(20) NOT NULL DEFAULT 'active',
			key_version INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_oauth_signing_keys_status ON oauth_signing_keys(status);
		CREATE INDEX IF NOT EXISTS idx_oauth_signing_keys_expires_at ON oauth_signing_keys(expires_at);
	`

	_, err := km.db.Pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create oauth_signing_keys table: %w", err)
	}

	return nil
}

// hashKey computes a hash of a key for fingerprinting
func (km *KeyManager) hashKey(key *rsa.PublicKey) string {
	// Create a fingerprint using SHA-256
	// This can be used for key identification
	nBytes := key.N.Bytes()
	h := sha256.Sum256(nBytes)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// KeyRotationStatus returns the status of key rotation
type KeyRotationStatus struct {
	CurrentKeyID      string    `json:"current_key_id"`
	CurrentKeyVersion int       `json:"current_key_version"`
	CurrentKeyExpires time.Time `json:"current_key_expires"`
	ShouldRotate      bool      `json:"should_rotate"`
	ActiveKeyCount    int       `json:"active_key_count"`
	RotatedKeyCount   int       `json:"rotated_key_count"`
}

// GetRotationStatus returns the current key rotation status
func (km *KeyManager) GetRotationStatus(ctx context.Context) (*KeyRotationStatus, error) {
	status := &KeyRotationStatus{
		CurrentKeyID:   km.currentKeyID,
		ShouldRotate:   km.ShouldRotateKey(),
	}

	// Get current key metadata
	err := km.db.Pool.QueryRow(ctx, `
		SELECT key_version, expires_at FROM oauth_signing_keys
		WHERE key_id = $1 AND status = 'active'
	`, km.currentKeyID).Scan(&status.CurrentKeyVersion, &status.CurrentKeyExpires)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("failed to get current key info: %w", err)
	}

	// Count active and rotated keys
	err = km.db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'active') as active_count,
			COUNT(*) FILTER (WHERE status = 'rotated') as rotated_count
		FROM oauth_signing_keys
	`).Scan(&status.ActiveKeyCount, &status.RotatedKeyCount)

	if err != nil {
		return nil, fmt.Errorf("failed to count keys: %w", err)
	}

	return status, nil
}
