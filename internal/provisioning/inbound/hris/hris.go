package hris

import (
	"context"

	"github.com/openidx/openidx/internal/provisioning"
)

// HRISAdapter defines the interface for HRIS connectors.
type HRISAdapter interface {
	// Sync synchronizes changes from the HRIS system.
	// It should return any errors encountered during the sync.
	Sync(ctx context.Context) error

	// Close closes any resources held by the adapter.
	Close() error
}

// HRISConfig represents the configuration for an HRIS connector.
type HRISConfig struct {
	// ID is the unique identifier for this connector instance.
	ID string
	// Type is the type of HRIS (e.g., "workday", "successfactors").
	Type string
	// Enabled indicates whether the connector is active.
	Enabled bool
	// Config contains type-specific configuration as key-value pairs.
	Config map[string]string
	// LastSync timestamp of the last successful sync.
	LastSync int64
	// SyncInterval is the interval in seconds between syncs.
	SyncInterval int
}
