// Package mfa provides Multi-Factor Authentication data persistence
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

// TOTPEnrollment represents a user's TOTP enrollment
type TOTPEnrollment struct {
	ID            uuid.UUID `json:"id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	Secret        string    `json:"-"` // Encrypted secret, never expose in JSON
	AccountName   string    `json:"account_name" db:"account_name"`
	Verified      bool      `json:"verified" db:"verified"`
	Enabled       bool      `json:"enabled" db:"enabled"`
	BackupCodes   []string  `json:"backup_codes,omitempty" db:"backup_codes"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// Repository defines the interface for MFA data operations
type Repository interface {
	// TOTP operations
	CreateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error
	GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*TOTPEnrollment, error)
	UpdateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error
	DeleteTOTP(ctx context.Context, userID uuid.UUID) error
	VerifyTOTP(ctx context.Context, userID uuid.UUID) error
	MarkTOTPUsed(ctx context.Context, userID uuid.UUID) error

	// Health check
	Ping(ctx context.Context) error
}

// PostgreSQLRepository implements Repository using PostgreSQL
type PostgreSQLRepository struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

// NewPostgreSQLRepository creates a new PostgreSQL repository for MFA
func NewPostgreSQLRepository(pool *pgxpool.Pool, logger *zap.Logger) *PostgreSQLRepository {
	return &PostgreSQLRepository{
		pool:   pool,
		logger: logger,
	}
}

// Ping checks if the database connection is alive
func (r *PostgreSQLRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

// CreateTOTP creates a new TOTP enrollment for a user
func (r *PostgreSQLRepository) CreateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal backup codes to JSON
	var backupCodesJSON []byte
	var err error
	if enrollment.BackupCodes != nil && len(enrollment.BackupCodes) > 0 {
		backupCodesJSON, err = json.Marshal(enrollment.BackupCodes)
		if err != nil {
			return fmt.Errorf("marshal backup codes: %w", err)
		}
	}

	query := `
		INSERT INTO mfa_totp (
			id, user_id, secret, account_name, verified, enabled,
			backup_codes, created_at, verified_at, last_used_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id) DO UPDATE SET
			secret = EXCLUDED.secret,
			account_name = EXCLUDED.account_name,
			verified = EXCLUDED.verified,
			enabled = EXCLUDED.enabled,
			backup_codes = EXCLUDED.backup_codes,
			verified_at = EXCLUDED.verified_at,
			last_used_at = EXCLUDED.last_used_at
	`

	_, err = r.pool.Exec(ctx, query,
		enrollment.ID,
		enrollment.UserID,
		enrollment.Secret,
		enrollment.AccountName,
		enrollment.Verified,
		enrollment.Enabled,
		backupCodesJSON,
		enrollment.CreatedAt,
		enrollment.VerifiedAt,
		enrollment.LastUsedAt,
	)

	if err != nil {
		return fmt.Errorf("insert totp enrollment: %w", err)
	}

	r.logger.Info("Created TOTP enrollment",
		zap.String("user_id", enrollment.UserID.String()),
		zap.Bool("verified", enrollment.Verified),
	)

	return nil
}

// GetTOTPByUserID retrieves a TOTP enrollment by user ID
func (r *PostgreSQLRepository) GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*TOTPEnrollment, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, user_id, secret, account_name, verified, enabled,
			backup_codes, created_at, verified_at, last_used_at
		FROM mfa_totp
		WHERE user_id = $1
	`

	return r.scanTOTP(r.pool.QueryRow(ctx, query, userID))
}

// UpdateTOTP updates an existing TOTP enrollment
func (r *PostgreSQLRepository) UpdateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal backup codes to JSON
	var backupCodesJSON []byte
	var err error
	if enrollment.BackupCodes != nil && len(enrollment.BackupCodes) > 0 {
		backupCodesJSON, err = json.Marshal(enrollment.BackupCodes)
		if err != nil {
			return fmt.Errorf("marshal backup codes: %w", err)
		}
	}

	query := `
		UPDATE mfa_totp SET
			secret = $2,
			account_name = $3,
			verified = $4,
			enabled = $5,
			backup_codes = $6,
			verified_at = $7,
			last_used_at = $8
		WHERE user_id = $1
	`

	result, err := r.pool.Exec(ctx, query,
		enrollment.UserID,
		enrollment.Secret,
		enrollment.AccountName,
		enrollment.Verified,
		enrollment.Enabled,
		backupCodesJSON,
		enrollment.VerifiedAt,
		enrollment.LastUsedAt,
	)

	if err != nil {
		return fmt.Errorf("update totp enrollment: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("totp enrollment not found for user: %s", enrollment.UserID.String())
	}

	r.logger.Info("Updated TOTP enrollment",
		zap.String("user_id", enrollment.UserID.String()),
		zap.Bool("verified", enrollment.Verified),
		zap.Bool("enabled", enrollment.Enabled),
	)

	return nil
}

// DeleteTOTP deletes a TOTP enrollment for a user
func (r *PostgreSQLRepository) DeleteTOTP(ctx context.Context, userID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `DELETE FROM mfa_totp WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete totp enrollment: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("totp enrollment not found for user: %s", userID.String())
	}

	r.logger.Info("Deleted TOTP enrollment",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// VerifyTOTP marks a TOTP enrollment as verified
func (r *PostgreSQLRepository) VerifyTOTP(ctx context.Context, userID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	now := time.Now()
	query := `
		UPDATE mfa_totp SET
			verified = true,
			verified_at = $2
		WHERE user_id = $1
	`

	result, err := r.pool.Exec(ctx, query, userID, now)
	if err != nil {
		return fmt.Errorf("verify totp enrollment: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("totp enrollment not found for user: %s", userID.String())
	}

	r.logger.Info("Verified TOTP enrollment",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// MarkTOTPUsed updates the last_used_at timestamp for a TOTP enrollment
func (r *PostgreSQLRepository) MarkTOTPUsed(ctx context.Context, userID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	now := time.Now()
	query := `
		UPDATE mfa_totp SET
			last_used_at = $2
		WHERE user_id = $1
	`

	_, err := r.pool.Exec(ctx, query, userID, now)
	if err != nil {
		return fmt.Errorf("mark totp used: %w", err)
	}

	return nil
}

// scanTOTP scans a TOTPEnrollment from a database row
func (r *PostgreSQLRepository) scanTOTP(row pgx.Row) (*TOTPEnrollment, error) {
	var enrollment TOTPEnrollment
	var backupCodesJSON []byte

	err := row.Scan(
		&enrollment.ID,
		&enrollment.UserID,
		&enrollment.Secret,
		&enrollment.AccountName,
		&enrollment.Verified,
		&enrollment.Enabled,
		&backupCodesJSON,
		&enrollment.CreatedAt,
		&enrollment.VerifiedAt,
		&enrollment.LastUsedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("totp enrollment not found")
		}
		return nil, fmt.Errorf("scan totp enrollment: %w", err)
	}

	// Unmarshal backup codes if present
	if len(backupCodesJSON) > 0 && string(backupCodesJSON) != "null" {
		if err := json.Unmarshal(backupCodesJSON, &enrollment.BackupCodes); err != nil {
			return nil, fmt.Errorf("unmarshal backup codes: %w", err)
		}
	}

	return &enrollment, nil
}
