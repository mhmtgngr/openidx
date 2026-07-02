package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Auditor is the subset of the unified audit service the vault uses. Satisfied
// by *access.UnifiedAuditService.RecordEvent.
type Auditor interface {
	RecordEvent(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error
}

// Service is the credential vault store.
type Service struct {
	db             *database.PostgresDB
	ring           *keyring
	audit          Auditor
	logger         *zap.Logger
	revealLeaseTTL time.Duration
}

func NewService(db *database.PostgresDB, ring *keyring, audit Auditor, revealLeaseTTL time.Duration, logger *zap.Logger) (*Service, error) {
	if ring == nil || !ring.Enabled() {
		return nil, errors.New("vault: keyring not enabled; refusing to start (fail-closed)")
	}
	if revealLeaseTTL <= 0 {
		revealLeaseTTL = 5 * time.Minute
	}
	return &Service{
		db:             db,
		ring:           ring,
		audit:          audit,
		logger:         logger.With(zap.String("component", "vault")),
		revealLeaseTTL: revealLeaseTTL,
	}, nil
}

// ---- DTOs (deliberately carry no value/ciphertext) ----

type SecretMeta struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Description    string    `json:"description,omitempty"`
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type VersionMeta struct {
	Version   int       `json:"version"`
	KeyID     int       `json:"key_id"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type SecretDetail struct {
	SecretMeta
	Versions []VersionMeta `json:"versions"`
}

type StoreInput struct {
	Name        string
	Type        string
	Description string
	Value       []byte
	Metadata    map[string]interface{}
	OwnerID     string
	CreatedBy   string
}

func (s *Service) orgID(ctx context.Context) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	return org.ID, nil
}

// Store creates a new secret at version 1. The plaintext is sealed and zeroed;
// it is never persisted, logged, or returned.
func (s *Service) Store(ctx context.Context, in StoreInput) (*SecretMeta, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return nil, err
	}
	if in.Type == "" {
		in.Type = "generic"
	}
	secretID := uuid.New().String()
	keyID, blob, err := s.ring.Seal(secretID, 1, in.Value)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	zero(in.Value)

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var meta SecretMeta
	err = tx.QueryRow(ctx, `
		INSERT INTO vault_secrets (id, org_id, name, type, description, owner_id, metadata, current_version, created_by)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid,$7,1,NULLIF($8,'')::uuid)
		RETURNING id, name, type, COALESCE(description,''), current_version, created_at, updated_at
	`, secretID, orgID, in.Name, in.Type, in.Description, in.OwnerID, jsonOrEmpty(in.Metadata), in.CreatedBy).
		Scan(&meta.ID, &meta.Name, &meta.Type, &meta.Description, &meta.CurrentVersion, &meta.CreatedAt, &meta.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		VALUES ($1,$2,1,$3,$4,NULLIF($5,'')::uuid)
	`, orgID, secretID, int(keyID), blob, in.CreatedBy); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.recordAudit(ctx, "vault.secret_created", in.CreatedBy, map[string]interface{}{"secret_id": secretID, "name": in.Name})
	return &meta, nil
}

// NewVersion appends an encrypted version and bumps current_version.
func (s *Service) NewVersion(ctx context.Context, secretID string, value []byte, by string) (int, error) {
	orgID, err := s.orgID(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var next int
	if err := tx.QueryRow(ctx,
		`UPDATE vault_secrets SET current_version = current_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING current_version`, secretID).Scan(&next); err != nil {
		return 0, err
	}
	keyID, blob, err := s.ring.Seal(secretID, next, value)
	if err != nil {
		return 0, err
	}
	zero(value)
	if _, err := tx.Exec(ctx,
		`INSERT INTO vault_secret_versions (org_id, secret_id, version, key_id, ciphertext, created_by)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid)`, orgID, secretID, next, int(keyID), blob, by); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	s.recordAudit(ctx, "vault.secret_version", by, map[string]interface{}{"secret_id": secretID, "version": next})
	return next, nil
}

func (s *Service) List(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.Type, &m.Description, &m.CurrentVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, secretID string) (*SecretDetail, error) {
	var d SecretDetail
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, type, COALESCE(description,''), current_version, created_at, updated_at
		FROM vault_secrets WHERE id = $1`, secretID).
		Scan(&d.ID, &d.Name, &d.Type, &d.Description, &d.CurrentVersion, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT version, key_id, COALESCE(created_by::text,''), created_at
		 FROM vault_secret_versions WHERE secret_id = $1 ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v VersionMeta
		if err := rows.Scan(&v.Version, &v.KeyID, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		d.Versions = append(d.Versions, v)
	}
	return &d, rows.Err()
}

// Delete removes the secret and (via cascade) all its versions — the only copy
// of the ciphertext — so the secret is cryptographically unrecoverable.
func (s *Service) Delete(ctx context.Context, secretID string) error {
	ct, err := s.db.Pool.Exec(ctx, `DELETE FROM vault_secrets WHERE id = $1`, secretID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.recordAudit(ctx, "vault.secret_deleted", "", map[string]interface{}{"secret_id": secretID})
	return nil
}

// ErrNotFound is returned when a requested secret does not exist.
var ErrNotFound = errors.New("vault: secret not found")

func (s *Service) recordAudit(ctx context.Context, eventType, userID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	if err := s.audit.RecordEvent(ctx, "vault", eventType, "", userID, "", details); err != nil {
		s.logger.Warn("vault audit failed", zap.String("event", eventType), zap.Error(err))
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func jsonOrEmpty(m map[string]interface{}) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}
