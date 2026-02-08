// Package access provides BrowZer bootstrapper target configuration management.
// The BrowZer bootstrapper reads targets from a config.json file (via nconf).
// This file generates that config from the database whenever BrowZer targets change.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// BrowZerTarget represents a single target entry for the bootstrapper
type BrowZerTarget struct {
	VHost          string `json:"vhost"`
	Service        string `json:"service"`
	Path           string `json:"path"`
	Scheme         string `json:"scheme"`
	IDPIssuerURL   string `json:"idp_issuer_base_url"`
	IDPClientID    string `json:"idp_client_id"`
}

// BrowZerTargetArray is the top-level structure the bootstrapper expects
type BrowZerTargetArray struct {
	TargetArray []BrowZerTarget `json:"targetArray"`
}

// BrowZerTargetManager handles generation and writing of bootstrapper targets
type BrowZerTargetManager struct {
	db          *database.PostgresDB
	logger      *zap.Logger
	targetsPath string
	mu          sync.Mutex
}

// NewBrowZerTargetManager creates a new target manager
func NewBrowZerTargetManager(db *database.PostgresDB, logger *zap.Logger, targetsPath string) *BrowZerTargetManager {
	return &BrowZerTargetManager{
		db:          db,
		logger:      logger.With(zap.String("component", "browzer_targets")),
		targetsPath: targetsPath,
	}
}

// GenerateBrowZerTargets queries the database for all BrowZer-enabled routes
// and builds the target configuration JSON for the bootstrapper.
func (tm *BrowZerTargetManager) GenerateBrowZerTargets(ctx context.Context) (*BrowZerTargetArray, error) {
	// Get OIDC settings from BrowZer config
	var oidcIssuer, oidcClientID string
	err := tm.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(oidc_issuer, ''), COALESCE(oidc_client_id, '')
		 FROM ziti_browzer_config WHERE enabled = true LIMIT 1`).Scan(&oidcIssuer, &oidcClientID)
	if err != nil {
		// No BrowZer config means no targets
		tm.logger.Debug("No BrowZer config found, generating empty targets", zap.Error(err))
		return &BrowZerTargetArray{TargetArray: []BrowZerTarget{}}, nil
	}

	// Query all routes that have both Ziti and BrowZer enabled
	rows, err := tm.db.Pool.Query(ctx,
		`SELECT from_url, ziti_service_name
		 FROM proxy_routes
		 WHERE ziti_enabled = true
		   AND browzer_enabled = true
		   AND ziti_service_name IS NOT NULL
		   AND ziti_service_name != ''
		   AND enabled = true
		 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query BrowZer-enabled routes: %w", err)
	}
	defer rows.Close()

	var targets []BrowZerTarget
	for rows.Next() {
		var fromURL, serviceName string
		if err := rows.Scan(&fromURL, &serviceName); err != nil {
			tm.logger.Warn("Failed to scan route row", zap.Error(err))
			continue
		}

		// Extract hostname from from_url (e.g., "http://demo.localtest.me" -> "demo.localtest.me")
		vhost := fromURL
		if parsed, err := url.Parse(fromURL); err == nil && parsed.Host != "" {
			vhost = parsed.Hostname()
		}

		targets = append(targets, BrowZerTarget{
			VHost:        vhost,
			Service:      serviceName,
			Path:         "/",
			Scheme:       "http",
			IDPIssuerURL: oidcIssuer,
			IDPClientID:  oidcClientID,
		})
	}

	if targets == nil {
		targets = []BrowZerTarget{}
	}

	tm.logger.Info("Generated BrowZer targets", zap.Int("count", len(targets)))
	return &BrowZerTargetArray{TargetArray: targets}, nil
}

// WriteBrowZerTargets generates the target config and writes it to the shared config file.
// The file is written in the nconf config.json format where the targets JSON is a string value.
func (tm *BrowZerTargetManager) WriteBrowZerTargets(ctx context.Context) error {
	if tm.targetsPath == "" {
		tm.logger.Debug("No targets path configured, skipping write")
		return nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	targets, err := tm.GenerateBrowZerTargets(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate targets: %w", err)
	}

	// The bootstrapper's nconf expects config.json with the targets as a JSON string value
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("failed to marshal targets: %w", err)
	}

	// Build the nconf config.json format
	configMap := map[string]string{
		"ZITI_BROWZER_BOOTSTRAPPER_TARGETS": string(targetsJSON),
	}
	configJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(tm.targetsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write atomically: write to temp file, then rename
	tmpPath := tm.targetsPath + ".tmp"
	if err := os.WriteFile(tmpPath, configJSON, 0644); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, tm.targetsPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	tm.logger.Info("BrowZer targets written",
		zap.String("path", tm.targetsPath),
		zap.Int("targets", len(targets.TargetArray)))
	return nil
}
