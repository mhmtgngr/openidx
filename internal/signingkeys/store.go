// Package signingkeys manages the install-wide OAuth token signing keys in
// the oauth_signing_keys table: one active signing key plus retired keys that
// remain valid for verification until their not_after grace expires.
//
// The oauth service signs with the active key and serves every verification
// key from JWKS; the admin service triggers rotation. Private keys are
// encrypted at rest with the same AES-256 cipher (ENCRYPTION_KEY) used for
// the legacy system_settings key and IdP client secrets; reads tolerate
// plaintext rows so a deployment without ENCRYPTION_KEY keeps working.
package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// LegacyKid is the key ID the pre-rotation implementation hardcoded into
// every token and the JWKS document. The legacy system_settings key is
// imported under this kid so tokens issued before the upgrade keep
// verifying against the same JWKS entry.
const LegacyKid = "openidx-key-1"

// DefaultGrace is how long a retired key stays servable from JWKS after
// rotation. It must comfortably exceed the longest JWT lifetime the service
// issues (access/ID tokens live hours; refresh tokens are opaque DB rows and
// don't depend on the signing key).
const DefaultGrace = 30 * 24 * time.Hour

// Key is one signing key row. Private is always populated on reads.
type Key struct {
	Kid         string
	Private     *rsa.PrivateKey
	Status      string // "active" or "retired"
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RetiredAt   *time.Time
	NotAfter    *time.Time
}

// Store reads and writes oauth_signing_keys.
type Store struct {
	pool   *pgxpool.Pool
	cipher *secretcrypt.Cipher
	logger *zap.Logger
}

// NewStore builds a Store. encryptionKey follows the same contract as the
// rest of the codebase: a 32-byte key enables AES-256 at rest; anything else
// degrades to plaintext storage with a warning.
func NewStore(pool *pgxpool.Pool, encryptionKey string, logger *zap.Logger) *Store {
	cipher, err := secretcrypt.New(encryptionKey)
	if err != nil {
		logger.Warn("OAuth signing keys will be stored WITHOUT encryption at rest (plaintext); set a 32-byte ENCRYPTION_KEY", zap.Error(err))
		cipher = secretcrypt.NewNoop()
	}
	return &Store{pool: pool, cipher: cipher, logger: logger}
}

// EnsureActive returns the active signing key, creating one if the table has
// none: the legacy key (from system_settings) is imported under LegacyKid
// when provided, otherwise a fresh 2048-bit key is generated. Concurrent
// service replicas racing here are safe — the partial unique index on
// status='active' makes the INSERT a no-op for the loser, which then reads
// the winner's key.
func (s *Store) EnsureActive(ctx context.Context, legacy *rsa.PrivateKey) (*Key, error) {
	if k, err := s.Active(ctx); err == nil {
		return k, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	kid := LegacyKid
	priv := legacy
	if priv == nil {
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
		kid = newKid()
		priv = generated
	}
	stored, err := s.encodeKey(priv)
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO oauth_signing_keys (kid, private_key_pem, status, activated_at)
		VALUES ($1, $2, 'active', NOW())
		ON CONFLICT (status) WHERE status = 'active' DO NOTHING
	`, kid, stored)
	if err != nil {
		return nil, fmt.Errorf("insert active signing key: %w", err)
	}
	return s.Active(ctx)
}

// Active returns the single active signing key (pgx.ErrNoRows if none).
func (s *Store) Active(ctx context.Context) (*Key, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT kid, private_key_pem, status, created_at, activated_at, retired_at, not_after
		  FROM oauth_signing_keys
		 WHERE status = 'active'
	`)
	return s.scanKey(row)
}

// VerificationKeys returns every key tokens may still carry: the active key
// first, then retired keys whose grace has not expired.
func (s *Store) VerificationKeys(ctx context.Context) ([]*Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kid, private_key_pem, status, created_at, activated_at, retired_at, not_after
		  FROM oauth_signing_keys
		 WHERE status = 'active'
		    OR (status = 'retired' AND (not_after IS NULL OR not_after > NOW()))
		 ORDER BY (status = 'active') DESC, activated_at DESC NULLS LAST
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*Key
	for rows.Next() {
		k, err := s.scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// Rotate generates a fresh 2048-bit key, makes it active, and retires the
// previous active key with the given verification grace (DefaultGrace when
// grace <= 0). Returns the new active key.
func (s *Store) Rotate(ctx context.Context, grace time.Duration) (*Key, error) {
	if grace <= 0 {
		grace = DefaultGrace
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	stored, err := s.encodeKey(priv)
	if err != nil {
		return nil, err
	}
	kid := newKid()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE oauth_signing_keys
		   SET status = 'retired', retired_at = NOW(), not_after = NOW() + $1::interval
		 WHERE status = 'active'
	`, fmt.Sprintf("%d seconds", int64(grace.Seconds()))); err != nil {
		return nil, fmt.Errorf("retire active signing key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_signing_keys (kid, private_key_pem, status, activated_at)
		VALUES ($1, $2, 'active', NOW())
	`, kid, stored); err != nil {
		return nil, fmt.Errorf("insert rotated signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.logger.Info("OAuth signing key rotated",
		zap.String("new_kid", kid),
		zap.Duration("previous_key_grace", grace))
	return s.Active(ctx)
}

// PruneExpired deletes retired keys whose verification grace has passed.
func (s *Store) PruneExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM oauth_signing_keys
		 WHERE status = 'retired' AND not_after IS NOT NULL AND not_after <= NOW()
	`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// List returns metadata for every key (private material never leaves the
// package through this path — callers get kid/status/timestamps only).
func (s *Store) List(ctx context.Context) ([]*Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kid, private_key_pem, status, created_at, activated_at, retired_at, not_after
		  FROM oauth_signing_keys
		 ORDER BY (status = 'active') DESC, created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*Key
	for rows.Next() {
		k, err := s.scanKey(rows)
		if err != nil {
			return nil, err
		}
		k.Private = nil
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) scanKey(row pgx.Row) (*Key, error) {
	var k Key
	var stored string
	if err := row.Scan(&k.Kid, &stored, &k.Status, &k.CreatedAt, &k.ActivatedAt, &k.RetiredAt, &k.NotAfter); err != nil {
		return nil, err
	}
	priv, err := s.decodeKey(stored)
	if err != nil {
		return nil, fmt.Errorf("decode signing key %s: %w", k.Kid, err)
	}
	k.Private = priv
	return &k, nil
}

func (s *Store) encodeKey(priv *rsa.PrivateKey) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	enc, err := s.cipher.Encrypt(string(pemBytes))
	if err != nil {
		return "", fmt.Errorf("encrypt signing key: %w", err)
	}
	return enc, nil
}

func (s *Store) decodeKey(stored string) (*rsa.PrivateKey, error) {
	pemStr := stored
	if secretcrypt.IsEncrypted(stored) {
		dec, err := s.cipher.Decrypt(stored)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		pemStr = dec
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func newKid() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is unrecoverable for key generation anyway;
		// this path only runs when rsa.GenerateKey already succeeded.
		return LegacyKid
	}
	return "openidx-key-" + hex.EncodeToString(buf)
}
