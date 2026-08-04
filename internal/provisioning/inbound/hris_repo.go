package inbound

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/provisioning/inbound/hris"
	"go.uber.org/zap"
)

// HRISRepository handles persistence of HRIS connector configurations.
type HRISRepository struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

// NewHRISRepository creates a new repository.
func NewHRISRepository(db *pgxpool.Pool, logger *zap.Logger) *HRISRepository {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &HRISRepository{
		db:     db,
		logger: logger,
	}
}

// GetAll retrieves all HRIS connector configurations.
func (r *HRISRepository) GetAll(ctx context.Context) ([]hris.HRISConfig, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, type, config, enabled, sync_interval, last_sync
		FROM hris_connectors
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query hris_connectors: %w", err)
	}
	defer rows.Close()

	var configs []hris.HRISConfig
	for rows.Next() {
		var c hris.HRISConfig
		var configJSON []byte
		if err := rows.Scan(
			&c.ID,
			&c.Type,
			&configJSON,
			&c.Enabled,
			&c.SyncInterval,
			&c.LastSync,
		); err != nil {
			return nil, fmt.Errorf("failed to scan hris_connector row: %w", err)
		}
		if err := json.Unmarshal(configJSON, &c.RawConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config for %s: %w", c.ID, err)
		}
		configs = append(configs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating hris_connectors: %w", err)
	}
	return configs, nil
}

// Save inserts or updates a connector configuration.
func (r *HRISRepository) Save(ctx context.Context, config hris.HRISConfig) error {
	configJSON, err := json.Marshal(config.RawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO hris_connectors (id, type, config, enabled, sync_interval, last_sync, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			config = EXCLUDED.config,
			enabled = EXCLUDED.enabled,
			sync_interval = EXCLUDED.sync_interval,
			last_sync = EXCLUDED.last_sync,
			updated_at = NOW()
	`,
		config.ID,
		c.Type,
		string(configJSON),
		c.Enabled,
		c.SyncInterval,
		c.LastSync,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert hris_connector: %w", err)
	}
	return nil
}

// Delete removes a connector configuration.
func (r *HRISRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM hris_connectors WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete hris_connector: %w", err)
	}
	return nil
}
