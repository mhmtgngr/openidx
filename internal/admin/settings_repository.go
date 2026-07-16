// Package admin: SettingsRepository isolates all access to the system_settings
// table behind one type, following the Repository pattern already proven in the
// identity (User/Group/Session) and oauth (OAuthClientStore) services — see
// docs/architecture/design-patterns-review.md.
//
// system_settings is a small key/value JSON store: one row per logical config
// blob (`system`, `sms_config`, `mfa_methods`, ...). Before this, every consumer
// in admin/service.go repeated the same
//
//	SELECT value FROM system_settings WHERE key = '<k>'
//	INSERT INTO system_settings (key, value, updated_at) VALUES ('<k>', $1, NOW())
//	  ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
//
// inline, so the read/write pool choice and the UPSERT shape could (and did)
// drift per call site. This centralizes it.
//
// Pool choice: reads use the PRIMARY on purpose. system_settings carries
// security policy (password policy, RequireMFA, lockout, session limits); an
// admin who just tightened a policy must see it take effect immediately
// (read-after-write), so we never risk replica lag here. This mirrors
// SessionRepository.IsValid, which also reads primary for a security decision.
// Writes are UPSERTs on the primary.
package admin

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
)

// ErrSettingNotFound is the sentinel returned when a settings key has no row.
var ErrSettingNotFound = errors.New("setting not found")

// SettingsRepository is the data-access port for the system_settings key/value
// store. Values are opaque JSON bytes; marshalling/defaulting is the caller's
// concern (settings shapes differ per key), keeping this type purely about
// storage and pool discipline.
type SettingsRepository interface {
	// GetRaw returns the raw JSON value for key, or ErrSettingNotFound if the key
	// is absent. Reads the PRIMARY (security-critical, read-after-write).
	GetRaw(ctx context.Context, key string) ([]byte, error)

	// PutRaw upserts the raw JSON value for key (primary).
	PutRaw(ctx context.Context, key string, value []byte) error
}

// PostgresSettingsRepository is the pgx implementation of SettingsRepository.
type PostgresSettingsRepository struct {
	db           *database.PostgresDB
	queryTimeout time.Duration
}

// NewPostgresSettingsRepository constructs the pgx-backed settings repository.
// The timeout bounds each query (mirrors the service's DB timeout discipline).
func NewPostgresSettingsRepository(db *database.PostgresDB) *PostgresSettingsRepository {
	return &PostgresSettingsRepository{db: db, queryTimeout: 5 * time.Second}
}

func (r *PostgresSettingsRepository) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.queryTimeout)
}

// GetRaw implements SettingsRepository. Reads the PRIMARY on purpose: settings
// gate security decisions, so a stale replica read is unacceptable.
func (r *PostgresSettingsRepository) GetRaw(ctx context.Context, key string) ([]byte, error) {
	if r == nil || r.db == nil || r.db.Pool == nil {
		return nil, errors.New("settings repository has no database")
	}
	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	var value []byte
	err := r.db.Pool.QueryRow(dbCtx,
		"SELECT value FROM system_settings WHERE key = $1", key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSettingNotFound
		}
		return nil, err
	}
	return value, nil
}

// PutRaw implements SettingsRepository. UPSERT on the primary.
func (r *PostgresSettingsRepository) PutRaw(ctx context.Context, key string, value []byte) error {
	if r == nil || r.db == nil || r.db.Pool == nil {
		return errors.New("settings repository has no database")
	}
	dbCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	_, err := r.db.Pool.Exec(dbCtx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
	`, key, value)
	return err
}
