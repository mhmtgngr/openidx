package directory

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// Scheduler runs periodic directory syncs
type Scheduler struct {
	db      *database.PostgresDB
	logger  *zap.Logger
	engine  *SyncEngine
	stopCh  chan struct{}
	running map[string]bool
	mu      sync.Mutex
}

// NewScheduler creates a new sync scheduler
func NewScheduler(db *database.PostgresDB, engine *SyncEngine, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		db:      db,
		logger:  logger.With(zap.String("component", "scheduler")),
		engine:  engine,
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}
}

// Start begins the scheduling loop
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.Info("Directory sync scheduler started")

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndRunSyncs(ctx)
		}
	}
}

// Stop halts the scheduler
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

// TriggerSync manually triggers a sync for a directory
func (s *Scheduler) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	s.mu.Lock()
	if s.running[directoryID] {
		s.mu.Unlock()
		return nil // already running
	}
	s.running[directoryID] = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.running, directoryID)
			s.mu.Unlock()
		}()

		// Use a background context — the triggering HTTP request context may be canceled
		bgCtx := context.Background()

		cfg, err := s.loadDirectoryConfig(bgCtx, directoryID)
		if err != nil {
			s.logger.Error("Failed to load directory config for sync", zap.String("id", directoryID), zap.Error(err))
			return
		}

		if _, err := s.engine.RunSync(bgCtx, directoryID, cfg, fullSync); err != nil {
			s.logger.Error("Directory sync failed", zap.String("id", directoryID), zap.Error(err))
		}
	}()

	return nil
}

func (s *Scheduler) checkAndRunSyncs(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, config FROM directory_integrations WHERE enabled = true`)
	if err != nil {
		s.logger.Error("Failed to query directories for scheduling", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var configBytes []byte
		if err := rows.Scan(&id, &configBytes); err != nil {
			continue
		}

		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			continue
		}

		if !cfg.SyncEnabled || cfg.SyncInterval <= 0 {
			continue
		}

		// Check if sync is due
		var lastSyncAt *time.Time
		s.db.Pool.QueryRow(ctx,
			`SELECT last_sync_at FROM directory_sync_state WHERE directory_id = $1`, id).Scan(&lastSyncAt)

		syncDue := false
		fullSync := false
		if lastSyncAt == nil {
			// Never synced — do full sync
			syncDue = true
			fullSync = true
		} else {
			elapsed := time.Since(*lastSyncAt)
			if elapsed >= time.Duration(cfg.SyncInterval)*time.Minute {
				syncDue = true
				// Do a full sync once per day, incremental otherwise
				if elapsed >= 24*time.Hour {
					fullSync = true
				}
			}
		}

		if syncDue {
			s.mu.Lock()
			alreadyRunning := s.running[id]
			s.mu.Unlock()

			if !alreadyRunning {
				s.logger.Info("Triggering scheduled sync",
					zap.String("directory_id", id),
					zap.Bool("full", fullSync),
				)
				s.TriggerSync(ctx, id, fullSync)
			}
		}
	}
}

func (s *Scheduler) loadDirectoryConfig(ctx context.Context, directoryID string) (LDAPConfig, error) {
	var configBytes []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT config FROM directory_integrations WHERE id = $1`, directoryID).Scan(&configBytes)
	if err != nil {
		return LDAPConfig{}, err
	}

	var cfg LDAPConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return LDAPConfig{}, err
	}

	return cfg, nil
}
