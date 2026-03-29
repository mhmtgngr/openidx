package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/transport"
)

// Agent orchestrates configuration syncing, check execution, and result reporting.
type Agent struct {
	logger    *zap.Logger
	config    *AgentConfig
	configDir string
	client    transport.Transport
	registry  *checks.Registry
	engine    *checks.Engine
	serverCfg *ServerConfig
}

// NewAgent loads the persisted agent config from configDir, creates a transport
// client, and initialises an empty check registry and engine.
func NewAgent(logger *zap.Logger, configDir string) (*Agent, error) {
	cfg, err := LoadConfig(configDir)
	if err != nil {
		return nil, fmt.Errorf("loading agent config: %w", err)
	}

	client := transport.NewTransport(cfg.ServerURL, cfg.AuthToken, cfg.ZitiIdentityFile, cfg.ZitiServiceName, logger)
	registry := checks.NewRegistry()
	engine := checks.NewEngine(registry)

	defaultCfg := DefaultServerConfig()
	a := &Agent{
		logger:    logger,
		config:    cfg,
		configDir: configDir,
		client:    client,
		registry:  registry,
		engine:    engine,
		serverCfg: &defaultCfg,
	}

	return a, nil
}

// RegisterBuiltinChecks registers the built-in check implementations with the
// agent's registry.
func (a *Agent) RegisterBuiltinChecks() {
	a.registry.Register("os_version", &checks.OSVersionCheck{})
	a.registry.Register("disk_encryption", &checks.DiskEncryptionCheck{})
	a.registry.Register("process_running", &checks.ProcessCheck{})
}

// SyncConfig fetches the server-side configuration via the transport client and
// parses it into a ServerConfig. On any error it falls back to DefaultServerConfig
// and logs a warning.
func (a *Agent) SyncConfig(ctx context.Context) error {
	data, err := a.client.GetConfig()
	if err != nil {
		def := DefaultServerConfig()
		a.serverCfg = &def
		a.logger.Warn("failed to fetch server config, using defaults", zap.Error(err))
		return fmt.Errorf("fetching server config: %w", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		def := DefaultServerConfig()
		a.serverCfg = &def
		a.logger.Warn("failed to parse server config, using defaults", zap.Error(err))
		return fmt.Errorf("parsing server config: %w", err)
	}

	a.serverCfg = &cfg
	a.logger.Info("server config synced", zap.Int("checks", len(cfg.Checks)))
	return nil
}

// reportPayload is the JSON body sent to the report endpoint.
type reportPayload struct {
	AgentID  string          `json:"agent_id"`
	DeviceID string          `json:"device_id"`
	Results  []engineResult  `json:"results"`
	ReportedAt time.Time     `json:"reported_at"`
}

type engineResult struct {
	CheckType   string                 `json:"check_type"`
	Severity    string                 `json:"severity"`
	Status      checks.Status          `json:"status"`
	Score       float64                `json:"score"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RanAt       time.Time              `json:"ran_at"`
}

// RunOnce performs a single sync-check-report cycle:
//  1. SyncConfig — fetch latest check config from the server.
//  2. Run all configured checks via the engine.
//  3. Marshal results and POST them to the report endpoint.
//
// SyncConfig errors are logged but do not abort the cycle; the agent proceeds
// with whatever config is currently loaded.
func (a *Agent) RunOnce(ctx context.Context) error {
	// Best-effort config sync; proceed even on failure.
	if err := a.SyncConfig(ctx); err != nil {
		a.logger.Warn("config sync failed, proceeding with cached config", zap.Error(err))
	}

	engineResults := a.engine.RunChecks(ctx, a.serverCfg.Checks)

	results := make([]engineResult, 0, len(engineResults))
	for _, er := range engineResults {
		results = append(results, engineResult{
			CheckType:   er.CheckType,
			Severity:    er.Severity,
			Status:      er.Result.Status,
			Score:       er.Result.Score,
			Message:     er.Result.Message,
			Remediation: er.Result.Remediation,
			Details:     er.Result.Details,
			RanAt:       er.RanAt,
		})
	}

	payload := reportPayload{
		AgentID:    a.config.AgentID,
		DeviceID:   a.config.DeviceID,
		Results:    results,
		ReportedAt: time.Now().UTC(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling report payload: %w", err)
	}

	if err := a.client.ReportResults(data); err != nil {
		return fmt.Errorf("reporting results: %w", err)
	}

	a.logger.Info("results reported", zap.Int("checks", len(results)))
	return nil
}

// Run executes an initial RunOnce cycle and then repeats on the interval
// specified by serverCfg.ReportInterval. It blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent starting", zap.String("agent_id", a.config.AgentID))

	if err := a.RunOnce(ctx); err != nil {
		a.logger.Error("initial run failed", zap.Error(err))
	}

	interval := parseInterval(a.serverCfg.ReportInterval, time.Hour)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent shutting down")
			return ctx.Err()
		case <-ticker.C:
			// Re-read interval in case SyncConfig updated serverCfg.
			newInterval := parseInterval(a.serverCfg.ReportInterval, time.Hour)
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}

			if err := a.RunOnce(ctx); err != nil {
				a.logger.Error("run cycle failed", zap.Error(err))
			}
		}
	}
}

// parseInterval parses a duration string, returning fallback on any error.
func parseInterval(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
