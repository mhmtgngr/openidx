package mock

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/provisioning"
	"github.com/openidx/openidx/internal/provisioning/inbound/hris"
	"go.uber.org/zap"
)

// MockConnector is a simple HRIS connector for development/testing.
type MockConnector struct {
	config hris.HRISConfig
	logger *zap.Logger
}

// NewMockConnector creates a new mock HRIS connector.
func NewMockConnector(config hris.HRISConfig, logger *zap.Logger) (*MockConnector, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &MockConnector{
		config: config,
		logger: logger,
	}, nil
}

// Sync simulates fetching changes from the HRIS.
// In a real implementation, this would query the HRIS API for changes since last sync.
func (c *MockConnector) Sync(ctx context.Context) error {
	c.logger.Info("Mock HRIS sync started", zap.String("id", c.config.ID))
	// Simulate some work
	time.Sleep(100 * time.Millisecond)

	// Generate some mock changes
	// In reality, we would convert HRIS changes to provisioning.UserChange events
	// and send them to the provisioning engine via an event bus or direct call.
	// For now, we just log.
	c.logger.Info("Mock HRIS sync completed", zap.String("id", c.config.ID),
		zap.Int("new_users", 2), zap.Int("updated_users", 1), zap.Int("terminated_users", 0))

	// Update last sync time in the config (in a real implementation, we'd persist this)
	c.config.LastSync = time.Now().Unix()
	return nil
}

// Close closes the connector.
func (c *MockConnector) Close() error {
	c.logger.Info("Closing mock HRIS connector", zap.String("id", c.config.ID))
	return nil
}
