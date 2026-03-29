package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openidx/openidx/agent/internal/checks"
)

// AgentConfig holds the persisted configuration for a registered agent.
type AgentConfig struct {
	ServerURL  string `json:"server_url"`
	AgentID    string `json:"agent_id"`
	DeviceID   string `json:"device_id"`
	EnrolledAt string `json:"enrolled_at"`
	AuthToken        string `json:"auth_token,omitempty"`
	ZitiIdentityFile string `json:"ziti_identity_file,omitempty"`
	ZitiServiceName  string `json:"ziti_service_name,omitempty"`
	PluginDir        string `json:"plugin_dir,omitempty"`
}

// CheckConfig is an alias for checks.CheckConfig so callers that import the
// agent package do not also need to import the checks package.
type CheckConfig = checks.CheckConfig

// ServerConfig holds the configuration delivered by the server to the agent.
type ServerConfig struct {
	Checks         []CheckConfig `json:"checks"`
	ReportInterval string        `json:"report_interval"`
}

// DefaultServerConfig returns a ServerConfig populated with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Checks: []CheckConfig{
			{
				Type:     "os_version",
				Severity: "high",
				Interval: "1h",
			},
			{
				Type:     "disk_encryption",
				Severity: "critical",
				Interval: "6h",
			},
			{
				Type:     "process_running",
				Severity: "medium",
				Interval: "15m",
			},
		},
		ReportInterval: "1h",
	}
}

const configFileName = "agent.json"

// Save marshals the AgentConfig to JSON and writes it to agent.json inside dir.
// The directory is created with mode 0700 if it does not already exist.
// The file is written with mode 0600.
func (c *AgentConfig) Save(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling agent config: %w", err)
	}

	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing agent config: %w", err)
	}

	return nil
}

// LoadConfig reads agent.json from dir and returns the parsed AgentConfig.
func LoadConfig(dir string) (*AgentConfig, error) {
	path := filepath.Join(dir, configFileName)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading agent config: %w", err)
	}

	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing agent config: %w", err)
	}

	return &cfg, nil
}
