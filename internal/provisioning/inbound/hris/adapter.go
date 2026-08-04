package hris

import (
	"context"

	"github.com/openidx/openidx/internal/provisioning"
)

// HRISAdapter defines the interface for HRIS connectors.
type HRISAdapter interface {
	// Sync performs a synchronization cycle, fetching changes from the HRIS
	// and processing them (e.g., creating/updating/deleting users in the IDP).
	// It should be idempotent and handle errors gracefully.
	Sync(ctx context.Context) error
	// Close releases any resources held by the connector.
	Close() error
}

// HRISConfig holds the configuration for an HRIS connector.
type HRISConfig struct {
	// ID is a unique identifier for this connector.
	ID string `json:"id"`
	// Enabled indicates whether the connector is active.
	Enabled bool `json:"enabled"`
	// SyncInterval is the interval in seconds between sync runs.
	// If 0, a default interval (e.g., 1 hour) is used.
	SyncInterval int `json:"sync_interval_seconds"`
	// LastSync is the Unix timestamp of the last successful sync.
	// This is used for incremental syncs.
	LastSync int64 `json:"last_sync,omitempty"`
	// Additional configuration specific to the connector type.
	// This is typically unmarshaled into a struct specific to the connector.
	RawConfig map[string]interface{} `json:"raw_config,omitempty"`
}
