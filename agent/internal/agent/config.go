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
	ServerURL        string `json:"server_url"`
	AgentID          string `json:"agent_id"`
	DeviceID         string `json:"device_id"`
	EnrolledAt       string `json:"enrolled_at"`
	AuthToken        string `json:"auth_token,omitempty"`
	ZitiIdentityFile string `json:"ziti_identity_file,omitempty"`
	ZitiServiceName  string `json:"ziti_service_name,omitempty"`
	PluginDir        string `json:"plugin_dir,omitempty"`
	// UpdateManifestURL, when set, enables self-update: the service polls this
	// JSON manifest and applies a newer published MSI. Empty disables it.
	UpdateManifestURL string `json:"update_manifest_url,omitempty"`
	// InsecureSkipVerify skips TLS verification for the signaling WebSocket
	// (dev/self-signed only). Defaults false. Mirrors the HTTP client posture.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// CheckConfig is an alias for checks.CheckConfig so callers that import the
// agent package do not also need to import the checks package.
type CheckConfig = checks.CheckConfig

// ServerConfig holds the configuration delivered by the server to the agent.
type ServerConfig struct {
	Checks         []CheckConfig       `json:"checks"`
	ReportInterval string              `json:"report_interval"`
	RemoteSupport  *RemoteSupportBlock `json:"remote_support,omitempty"`
}

// RemoteSupportBlock is the in-flight remote-support session pointer the server
// embeds in the agent config when an admin has started a session for this
// device. When ConsentRequired is true, the person at the device must grant the
// session (via ConsentPath) before the admin can view/control.
type RemoteSupportBlock struct {
	SessionID       string          `json:"session_id"`
	Mode            string          `json:"mode"`
	WSPath          string          `json:"ws_path"`
	Recording       bool            `json:"recording"`
	ConsentRequired bool            `json:"consent_required"`
	ConsentStatus   string          `json:"consent_status"`
	ConsentPath     string          `json:"consent_path"`
	ICEServersRaw   json.RawMessage `json:"ice_servers,omitempty"`
	// ZitiService, when set by the server, is the Ziti overlay service the
	// device should dial to reach the signaling broker (zero-trust). Empty =
	// dial the public WSS via ServerURL.
	ZitiService string `json:"ziti_service,omitempty"`
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
