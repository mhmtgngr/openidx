package inbound

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/provisioning/inbound/hris"
)

package inbound

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/provisioning/inbound/hris"
)

// Scheduler manages the periodic execution of HRIS connectors.
type Scheduler struct {
	cron    *cron.Cron
	jobs    map[string]cron.EntryID
	logger  *zap.Logger
	mu      sync.RWMutex
	connectors map[string]hris.HRISAdapter
	configs  map[string]hris.HRISConfig
}

// NewScheduler creates a new Scheduler.
func NewScheduler(logger *zap.Logger) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{
		cron:       cron.New(),
		jobs:       make(map[string]cron.EntryID),
		logger:     logger,
		connectors: make(map[string]hris.HRISAdapter),
		configs:    make(map[string]hris.HRISConfig),
	}
}

// Start begins the scheduler.
func (s *Scheduler) Start() {
	s.cron.Start()
	s.logger.Info("HRIS inbound scheduler started")
}

// Stop stops the scheduler and waits for running jobs to complete.
func (s *Scheduler) Stop() {
	s.cron.Stop()
	s.logger.Info("HRIS inbound scheduler stopped")
}

// RegisterConnector adds a connector to be scheduled.
func (s *Scheduler) RegisterConnector(ctx context.Context, config hris.HRISConfig, adapter hris.HRISAdapter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if config.ID == "" {
		return fmt.Errorf("connector ID is required")
	}
	if !config.Enabled {
		s.logger.Info("Skipping disabled HRIS connector", zap.String("id", config.ID))
		return nil
	}

	// Store the connector and its config
	s.connectors[config.ID] = adapter
	s.configs[config.ID] = config

	// Schedule the sync job
	schedule := fmt.Sprintf("@every %ds", config.SyncInterval)
	if config.SyncInterval <= 0 {
		schedule = "@every 1h" // default
	}
	entryID, err := s.cron.AddFunc(schedule, func() {
		s.runSync(context.Background(), config.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to schedule connector %s: %w", config.ID, err)
	}
	s.jobs[config.ID] = entryID
	s.logger.Info("Registered HRIS connector", zap.String("id", config.ID), zap.String("schedule", schedule))

	// Run an initial sync if it's never been synced or if forced
	if config.LastSync == 0 {
		go s.runSync(ctx, config.ID)
	}
	return nil
}

// UnregisterConnector removes a connector from the scheduler.
func (s *Scheduler) UnregisterConnector(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entryID, exists := s.jobs[id]; exists {
		s.cron.Remove(entryID)
		delete(s.jobs, id)
	}
	if _, exists := s.connectors[id]; exists {
		delete(s.connectors, id)
		delete(s.configs, id)
	}
	if adapter, exists := s.connectors[id]; exists {
		if err := adapter.Close(); err != nil {
			s.logger.Error("Error closing HRIS connector", zap.String("id", id), zap.Error(err))
		}
		delete(s.connectors, id)
	}
	s.logger.Info("Unregistered HRIS connector", zap.String("id", id))
	return nil
}

// runSync performs the sync for a given connector.
func (s *Scheduler) runSync(ctx context.Context, id string) {
	s.mu.RLock()
	adapter, ok := s.connectors[id]
	s.mu.RUnlock()
	if !ok {
		s.logger.Error("HRIS connector not found", zap.String("id", id))
		return
	}

	start := time.Now()
	s.logger.Info("Starting HRIS sync", zap.String("id", id))
	if err := adapter.Sync(ctx); err != nil {
		s.logger.Error("HRIS sync failed", zap.String("id", id), zap.Error(err))
		// TODO: update error metrics
	} else {
		s.logger.Info("HRIS sync completed", zap.String("id", id), zap.Duration("took", time.Since(start)))
		// Update last sync time in the stored config
		s.mu.Lock()
		if config, exists := s.configs[id]; exists {
			config.LastSync = time.Now().Unix()
			s.configs[id] = config
		}
		s.mu.Unlock()
	}
}
