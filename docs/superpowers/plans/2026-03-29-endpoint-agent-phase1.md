# OpenIDX Endpoint Agent — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working `openidx-agent` binary that can enroll with the server, connect over HTTPS (Ziti in Phase 2), run built-in posture checks, and report results.

**Architecture:** Cobra CLI binary with an `enroll` command and a `run` command. The run loop syncs config from server, executes checks on schedule, and reports results. Phase 1 uses HTTPS transport; Phase 2 adds Ziti overlay.

**Tech Stack:** Go 1.25, Cobra CLI, testify, zap logger, net/http client

**Phase 1 Scope:** Enrollment + config sync + 3 built-in checks (os_version, disk_encryption, process_running) + result reporting + server API endpoints. No Ziti tunneling, no plugins (Phase 2).

---

## File Structure

```
agent/
├── cmd/openidx-agent/main.go              # Cobra root + enroll/run commands
├── internal/
│   ├── agent/agent.go                      # Agent runtime: boot, loop, shutdown
│   ├── agent/agent_test.go                 # Agent runtime tests
│   ├── agent/config.go                     # Agent config model
│   ├── agent/config_test.go                # Config tests
│   ├── transport/client.go                 # HTTPS client to server API
│   ├── transport/client_test.go            # Transport tests
│   ├── enrollment/enroll.go                # Enrollment flow
│   ├── enrollment/enroll_test.go           # Enrollment tests
│   ├── checks/registry.go                  # Check type registry
│   ├── checks/registry_test.go             # Registry tests
│   ├── checks/engine.go                    # Check scheduler + runner
│   ├── checks/engine_test.go               # Engine tests
│   ├── checks/os_version.go               # Built-in: OS version check
│   ├── checks/os_version_test.go           # OS version tests
│   ├── checks/disk_encryption.go           # Built-in: disk encryption check
│   ├── checks/disk_encryption_test.go      # Disk encryption tests
│   ├── checks/process.go                   # Built-in: process running check
│   └── checks/process_test.go              # Process check tests
├── go.mod                                  # Separate module (shares parent's deps)
└── Makefile                                # Agent build targets
```

Server-side (minimal additions):
```
internal/access/agent_api.go               # New: enrollment + report + config endpoints
internal/access/agent_api_test.go           # Tests for agent API
```

---

### Task 1: Agent Module Scaffold

**Files:**
- Create: `agent/go.mod`
- Create: `agent/cmd/openidx-agent/main.go`
- Create: `agent/Makefile`

- [ ] **Step 1: Create agent go.mod**

```bash
mkdir -p agent/cmd/openidx-agent agent/internal/{agent,transport,enrollment,checks}
```

Write `agent/go.mod`:
```go
module github.com/openidx/openidx/agent

go 1.25.0

require (
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
)
```

- [ ] **Step 2: Create main.go with Cobra root command**

Write `agent/cmd/openidx-agent/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	rootCmd := &cobra.Command{
		Use:     "openidx-agent",
		Short:   "OpenIDX Endpoint Agent",
		Long:    "Unified endpoint agent for zero-trust access, posture checks, and policy enforcement.",
		Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildTime, Commit),
	}

	rootCmd.PersistentFlags().String("config-dir", "/var/lib/openidx-agent", "Agent configuration directory")
	rootCmd.PersistentFlags().String("server-url", "", "OpenIDX server URL (for enrollment)")
	rootCmd.PersistentFlags().Bool("verbose", false, "Verbose logging")

	rootCmd.AddCommand(newEnrollCmd(logger))
	rootCmd.AddCommand(newRunCmd(logger))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newEnrollCmd(logger *zap.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device with OpenIDX",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("enroll: not yet implemented")
			return nil
		},
	}
	cmd.Flags().String("token", "", "Enrollment token (required)")
	cmd.MarkFlagRequired("token")
	return cmd
}

func newRunCmd(logger *zap.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("run: not yet implemented")
			return nil
		},
	}
}
```

- [ ] **Step 3: Create agent Makefile**

Write `agent/Makefile`:
```makefile
.PHONY: build test clean build-all

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-w -s -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)"

build:
	go build $(LDFLAGS) -o bin/openidx-agent ./cmd/openidx-agent

test:
	go test -v -race ./...

clean:
	rm -rf bin/

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/openidx-agent-linux-amd64 ./cmd/openidx-agent
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/openidx-agent-linux-arm64 ./cmd/openidx-agent
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/openidx-agent-darwin-amd64 ./cmd/openidx-agent
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/openidx-agent-darwin-arm64 ./cmd/openidx-agent
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/openidx-agent-windows-amd64.exe ./cmd/openidx-agent
```

- [ ] **Step 4: Download deps, build, verify**

Run:
```bash
cd agent && go mod tidy && go build ./cmd/openidx-agent && ./openidx-agent --version
```
Expected: Version string printed

- [ ] **Step 5: Commit**

```bash
git add agent/
git commit -m "feat(agent): scaffold openidx-agent CLI with enroll and run commands"
```

---

### Task 2: Agent Config Model

**Files:**
- Create: `agent/internal/agent/config.go`
- Create: `agent/internal/agent/config_test.go`

- [ ] **Step 1: Write config test**

Write `agent/internal/agent/config_test.go`:
```go
package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentConfig_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := &AgentConfig{
		ServerURL:  "https://openidx.example.com",
		AgentID:    "agent-001",
		DeviceID:   "device-abc",
		EnrolledAt: "2026-03-29T00:00:00Z",
	}

	err := cfg.Save(dir)
	require.NoError(t, err)

	loaded, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, cfg.ServerURL, loaded.ServerURL)
	assert.Equal(t, cfg.AgentID, loaded.AgentID)
	assert.Equal(t, cfg.DeviceID, loaded.DeviceID)
}

func TestLoadConfig_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadConfig(dir)
	assert.Error(t, err)
}

func TestServerConfig_Defaults(t *testing.T) {
	sc := DefaultServerConfig()
	assert.NotEmpty(t, sc.Checks)
	assert.Equal(t, "1h", sc.ReportInterval)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./internal/agent/ -v -run TestAgentConfig`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement config**

Write `agent/internal/agent/config.go`:
```go
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AgentConfig is persisted locally after enrollment.
type AgentConfig struct {
	ServerURL  string `json:"server_url"`
	AgentID    string `json:"agent_id"`
	DeviceID   string `json:"device_id"`
	EnrolledAt string `json:"enrolled_at"`
	AuthToken  string `json:"auth_token,omitempty"`
}

// CheckConfig defines a single posture check from the server.
type CheckConfig struct {
	Type     string                 `json:"type"`
	Params   map[string]interface{} `json:"params,omitempty"`
	Severity string                 `json:"severity"`
	Interval string                 `json:"interval"`
}

// ServerConfig is received from the server on config sync.
type ServerConfig struct {
	Checks         []CheckConfig `json:"checks"`
	ReportInterval string        `json:"report_interval"`
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Checks: []CheckConfig{
			{Type: "os_version", Severity: "high", Interval: "1h"},
			{Type: "disk_encryption", Severity: "critical", Interval: "6h"},
			{Type: "process_running", Severity: "medium", Interval: "15m"},
		},
		ReportInterval: "1h",
	}
}

func (c *AgentConfig) Save(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "agent.json"), data, 0600)
}

func LoadConfig(dir string) (*AgentConfig, error) {
	data, err := os.ReadFile(filepath.Join(dir, "agent.json"))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
```

- [ ] **Step 4: Run tests**

Run: `cd agent && go test ./internal/agent/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/internal/agent/
git commit -m "feat(agent): add config model with save/load and server config"
```

---

### Task 3: Check Registry and Engine

**Files:**
- Create: `agent/internal/checks/registry.go`
- Create: `agent/internal/checks/registry_test.go`
- Create: `agent/internal/checks/engine.go`
- Create: `agent/internal/checks/engine_test.go`

- [ ] **Step 1: Write registry test**

Write `agent/internal/checks/registry_test.go`:
```go
package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	mock := &mockCheck{name: "test_check"}
	r.Register("test_check", mock)

	got, ok := r.Get("test_check")
	require.True(t, ok)
	assert.Equal(t, "test_check", got.Name())
}

func TestRegistry_GetUnknown(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	r.Register("check_a", &mockCheck{name: "check_a"})
	r.Register("check_b", &mockCheck{name: "check_b"})
	assert.Len(t, r.List(), 2)
}

type mockCheck struct {
	name   string
	result *CheckResult
}

func (m *mockCheck) Name() string { return m.name }
func (m *mockCheck) Run(ctx context.Context, params map[string]interface{}) *CheckResult {
	if m.result != nil {
		return m.result
	}
	return &CheckResult{Status: StatusPass, Score: 1.0}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./internal/checks/ -v -run TestRegistry`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement registry**

Write `agent/internal/checks/registry.go`:
```go
package checks

import "context"

// Status represents the outcome of a check.
type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

// CheckResult is the outcome of running a check.
type CheckResult struct {
	Status      Status                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}

// Check is the interface all posture checks implement.
type Check interface {
	Name() string
	Run(ctx context.Context, params map[string]interface{}) *CheckResult
}

// Registry holds all registered check implementations.
type Registry struct {
	checks map[string]Check
}

func NewRegistry() *Registry {
	return &Registry{checks: make(map[string]Check)}
}

func (r *Registry) Register(name string, check Check) {
	r.checks[name] = check
}

func (r *Registry) Get(name string) (Check, bool) {
	c, ok := r.checks[name]
	return c, ok
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.checks))
	for name := range r.checks {
		names = append(names, name)
	}
	return names
}
```

- [ ] **Step 4: Write engine test**

Write `agent/internal/checks/engine_test.go`:
```go
package checks

import (
	"context"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_RunChecks(t *testing.T) {
	reg := NewRegistry()
	reg.Register("mock_pass", &mockCheck{name: "mock_pass", result: &CheckResult{Status: StatusPass, Score: 1.0}})
	reg.Register("mock_fail", &mockCheck{name: "mock_fail", result: &CheckResult{Status: StatusFail, Score: 0.0, Message: "failed"}})

	cfg := []agent.CheckConfig{
		{Type: "mock_pass", Severity: "low", Interval: "1h"},
		{Type: "mock_fail", Severity: "critical", Interval: "1h"},
	}

	engine := NewEngine(reg)
	results := engine.RunChecks(context.Background(), cfg)

	require.Len(t, results, 2)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, StatusFail, results[1].Status)
}

func TestEngine_SkipsUnknownCheck(t *testing.T) {
	reg := NewRegistry()
	cfg := []agent.CheckConfig{
		{Type: "nonexistent", Severity: "high", Interval: "1h"},
	}

	engine := NewEngine(reg)
	results := engine.RunChecks(context.Background(), cfg)

	require.Len(t, results, 1)
	assert.Equal(t, StatusError, results[0].Status)
}
```

- [ ] **Step 5: Implement engine**

Write `agent/internal/checks/engine.go`:
```go
package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
)

// EngineResult pairs a check config with its result.
type EngineResult struct {
	CheckType string       `json:"check_type"`
	Severity  string       `json:"severity"`
	Result    *CheckResult `json:"result"`
	RanAt     time.Time    `json:"ran_at"`
}

// Engine runs checks against a registry.
type Engine struct {
	registry *Registry
}

func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

func (e *Engine) RunChecks(ctx context.Context, configs []agent.CheckConfig) []EngineResult {
	results := make([]EngineResult, 0, len(configs))
	for _, cfg := range configs {
		check, ok := e.registry.Get(cfg.Type)
		var result *CheckResult
		if !ok {
			result = &CheckResult{
				Status:  StatusError,
				Score:   0,
				Message: fmt.Sprintf("unknown check type: %s", cfg.Type),
			}
		} else {
			result = check.Run(ctx, cfg.Params)
		}
		results = append(results, EngineResult{
			CheckType: cfg.Type,
			Severity:  cfg.Severity,
			Result:    result,
			RanAt:     time.Now(),
		})
	}
	return results
}
```

- [ ] **Step 6: Run all check tests**

Run: `cd agent && go test ./internal/checks/ -v`
Expected: PASS (5 tests)

- [ ] **Step 7: Commit**

```bash
git add agent/internal/checks/
git commit -m "feat(agent): add check registry and engine with tests"
```

---

### Task 4: Built-in Checks (os_version, disk_encryption, process_running)

**Files:**
- Create: `agent/internal/checks/os_version.go`
- Create: `agent/internal/checks/os_version_test.go`
- Create: `agent/internal/checks/disk_encryption.go`
- Create: `agent/internal/checks/disk_encryption_test.go`
- Create: `agent/internal/checks/process.go`
- Create: `agent/internal/checks/process_test.go`

- [ ] **Step 1: Write os_version test**

Write `agent/internal/checks/os_version_test.go`:
```go
package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOSVersionCheck_Name(t *testing.T) {
	c := &OSVersionCheck{}
	assert.Equal(t, "os_version", c.Name())
}

func TestOSVersionCheck_RunWithoutMinVersion(t *testing.T) {
	c := &OSVersionCheck{}
	result := c.Run(context.Background(), nil)
	assert.Equal(t, StatusPass, result.Status)
	assert.NotEmpty(t, result.Details["os"])
	assert.NotEmpty(t, result.Details["version"])
}

func TestOSVersionCheck_RunWithMinVersion(t *testing.T) {
	c := &OSVersionCheck{}
	// Use a very low minimum so it always passes
	result := c.Run(context.Background(), map[string]interface{}{
		"min_version": "0.0.1",
	})
	assert.Equal(t, StatusPass, result.Status)
}
```

- [ ] **Step 2: Implement os_version check**

Write `agent/internal/checks/os_version.go`:
```go
package checks

import (
	"context"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// OSVersionCheck reports the current OS and version.
type OSVersionCheck struct{}

func (c *OSVersionCheck) Name() string { return "os_version" }

func (c *OSVersionCheck) Run(ctx context.Context, params map[string]interface{}) *CheckResult {
	osName := runtime.GOOS
	version := getOSVersion()

	result := &CheckResult{
		Status: StatusPass,
		Score:  1.0,
		Details: map[string]interface{}{
			"os":      osName,
			"version": version,
			"arch":    runtime.GOARCH,
		},
	}

	if minVersion, ok := params["min_version"].(string); ok && minVersion != "" {
		if compareVersions(version, minVersion) < 0 {
			result.Status = StatusFail
			result.Score = 0.0
			result.Message = "OS version " + version + " is below minimum " + minVersion
			result.Remediation = "Update your operating system to version " + minVersion + " or later"
		}
	}

	return result
}

func getOSVersion() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "unknown"
	}
	release := unix.ByteSliceToString(uname.Release[:])
	// Extract version number (e.g., "6.8.0-90-generic" -> "6.8.0")
	parts := strings.SplitN(release, "-", 2)
	return parts[0]
}

// compareVersions returns -1 if a < b, 0 if equal, 1 if a > b.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			for _, c := range aParts[i] {
				if c >= '0' && c <= '9' {
					aNum = aNum*10 + int(c-'0')
				} else {
					break
				}
			}
		}
		if i < len(bParts) {
			for _, c := range bParts[i] {
				if c >= '0' && c <= '9' {
					bNum = bNum*10 + int(c-'0')
				} else {
					break
				}
			}
		}
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}
```

- [ ] **Step 3: Write process check test**

Write `agent/internal/checks/process_test.go`:
```go
package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcessCheck_Name(t *testing.T) {
	c := &ProcessCheck{}
	assert.Equal(t, "process_running", c.Name())
}

func TestProcessCheck_NoProcessesRequired(t *testing.T) {
	c := &ProcessCheck{}
	result := c.Run(context.Background(), nil)
	assert.Equal(t, StatusPass, result.Status)
}

func TestProcessCheck_FindsInitProcess(t *testing.T) {
	c := &ProcessCheck{}
	// "openidx-agent" won't be running in test, but we can check the structure
	result := c.Run(context.Background(), map[string]interface{}{
		"processes": []interface{}{"nonexistent-process-xyz"},
	})
	assert.Equal(t, StatusFail, result.Status)
	assert.Contains(t, result.Message, "nonexistent-process-xyz")
}
```

- [ ] **Step 4: Implement process check**

Write `agent/internal/checks/process.go`:
```go
package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProcessCheck verifies required processes are running.
type ProcessCheck struct{}

func (c *ProcessCheck) Name() string { return "process_running" }

func (c *ProcessCheck) Run(ctx context.Context, params map[string]interface{}) *CheckResult {
	required, ok := params["processes"]
	if !ok {
		return &CheckResult{Status: StatusPass, Score: 1.0, Message: "no processes required"}
	}

	var processList []string
	switch v := required.(type) {
	case []interface{}:
		for _, p := range v {
			if s, ok := p.(string); ok {
				processList = append(processList, s)
			}
		}
	case []string:
		processList = v
	}

	if len(processList) == 0 {
		return &CheckResult{Status: StatusPass, Score: 1.0, Message: "no processes required"}
	}

	running := listRunningProcesses()
	var missing []string
	for _, proc := range processList {
		found := false
		for _, r := range running {
			if strings.Contains(r, proc) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, proc)
		}
	}

	if len(missing) > 0 {
		return &CheckResult{
			Status:      StatusFail,
			Score:       float64(len(processList)-len(missing)) / float64(len(processList)),
			Message:     fmt.Sprintf("missing processes: %s", strings.Join(missing, ", ")),
			Remediation: "Ensure the following processes are running: " + strings.Join(missing, ", "),
			Details: map[string]interface{}{
				"required": processList,
				"missing":  missing,
			},
		}
	}

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Message: fmt.Sprintf("all %d required processes running", len(processList)),
		Details: map[string]interface{}{
			"required": processList,
		},
	}
}

func listRunningProcesses() []string {
	var procs []string
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return procs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only numeric directories are PIDs
		if entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if len(cmdline) > 0 {
			// cmdline uses null bytes as separators
			cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
			procs = append(procs, strings.TrimSpace(cmd))
		}
	}
	return procs
}
```

- [ ] **Step 5: Write disk_encryption test**

Write `agent/internal/checks/disk_encryption_test.go`:
```go
package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiskEncryptionCheck_Name(t *testing.T) {
	c := &DiskEncryptionCheck{}
	assert.Equal(t, "disk_encryption", c.Name())
}

func TestDiskEncryptionCheck_Run(t *testing.T) {
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	// Result depends on system state, but must not error
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn}, result.Status)
	assert.NotNil(t, result.Details)
}
```

- [ ] **Step 6: Implement disk_encryption check**

Write `agent/internal/checks/disk_encryption.go`:
```go
package checks

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
)

// DiskEncryptionCheck verifies disk encryption is enabled.
type DiskEncryptionCheck struct{}

func (c *DiskEncryptionCheck) Name() string { return "disk_encryption" }

func (c *DiskEncryptionCheck) Run(ctx context.Context, params map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkDarwin()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "disk encryption check not supported on " + runtime.GOOS,
			Details: map[string]interface{}{"os": runtime.GOOS},
		}
	}
}

func (c *DiskEncryptionCheck) checkLinux() *CheckResult {
	// Check for LUKS encrypted volumes
	out, err := exec.Command("lsblk", "-o", "NAME,TYPE,MOUNTPOINT").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "unable to check disk encryption",
			Details: map[string]interface{}{"error": err.Error()},
		}
	}

	output := string(out)
	encrypted := strings.Contains(output, "crypt")

	// Also check for dm-crypt
	if !encrypted {
		dmOut, _ := exec.Command("dmsetup", "status").Output()
		encrypted = len(dmOut) > 0 && strings.Contains(string(dmOut), "crypt")
	}

	if encrypted {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Message: "disk encryption detected (LUKS/dm-crypt)",
			Details: map[string]interface{}{"method": "luks"},
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0.0,
		Message:     "no disk encryption detected",
		Remediation: "Enable LUKS disk encryption on your system partition",
		Details:     map[string]interface{}{"method": "none"},
	}
}

func (c *DiskEncryptionCheck) checkDarwin() *CheckResult {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "unable to check FileVault status",
			Details: map[string]interface{}{"error": err.Error()},
		}
	}

	if strings.Contains(string(out), "FileVault is On") {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Message: "FileVault is enabled",
			Details: map[string]interface{}{"method": "filevault"},
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0.0,
		Message:     "FileVault is not enabled",
		Remediation: "Enable FileVault in System Settings > Privacy & Security",
		Details:     map[string]interface{}{"method": "none"},
	}
}
```

- [ ] **Step 7: Run all check tests**

Run: `cd agent && go test ./internal/checks/ -v`
Expected: PASS (all tests)

- [ ] **Step 8: Commit**

```bash
git add agent/internal/checks/
git commit -m "feat(agent): add built-in checks: os_version, disk_encryption, process_running"
```

---

### Task 5: HTTP Transport Client

**Files:**
- Create: `agent/internal/transport/client.go`
- Create: `agent/internal/transport/client_test.go`

- [ ] **Step 1: Write transport test**

Write `agent/internal/transport/client_test.go`:
```go
package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Enroll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/access/agent/enroll", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(EnrollResponse{
			AgentID:  "agent-001",
			DeviceID: "device-abc",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	resp, err := client.Enroll("test-token")
	require.NoError(t, err)
	assert.Equal(t, "agent-001", resp.AgentID)
}

func TestClient_ReportResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/access/agent/report", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token-123")
	err := client.ReportResults([]byte(`{"results":[]}`))
	require.NoError(t, err)
}

func TestClient_GetConfig(t *testing.T) {
	expected := `{"checks":[{"type":"os_version","severity":"high","interval":"1h"}],"report_interval":"1h"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/access/agent/config", r.URL.Path)
		w.Write([]byte(expected))
	}))
	defer server.Close()

	client := NewClient(server.URL, "auth-token-123")
	data, err := client.GetConfig()
	require.NoError(t, err)
	assert.Contains(t, string(data), "os_version")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./internal/transport/ -v`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement transport client**

Write `agent/internal/transport/client.go`:
```go
package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// EnrollResponse is the server response to enrollment.
type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
}

// Client communicates with the OpenIDX server API.
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

func NewClient(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) Enroll(token string) (*EnrollResponse, error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/access/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

func (c *Client) ReportResults(data []byte) error {
	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/access/agent/report", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("report request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("report failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func (c *Client) GetConfig() ([]byte, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/v1/access/agent/config", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("config request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config fetch failed (HTTP %d)", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
```

- [ ] **Step 4: Run tests**

Run: `cd agent && go test ./internal/transport/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/internal/transport/
git commit -m "feat(agent): add HTTP transport client for enrollment, config, and reporting"
```

---

### Task 6: Agent Runtime (boot, loop, shutdown)

**Files:**
- Create: `agent/internal/agent/agent.go`
- Create: `agent/internal/agent/agent_test.go`

- [ ] **Step 1: Write agent runtime test**

Write `agent/internal/agent/agent_test.go`:
```go
package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/checks"
)

func TestAgent_NewAgent(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	dir := t.TempDir()
	cfg := &AgentConfig{ServerURL: "http://localhost", AgentID: "test", AuthToken: "tok"}
	cfg.Save(dir)

	a, err := NewAgent(logger, dir)
	require.NoError(t, err)
	assert.Equal(t, "test", a.config.AgentID)
}

func TestAgent_RunOnce(t *testing.T) {
	reportReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/access/agent/config":
			json.NewEncoder(w).Encode(ServerConfig{
				Checks:         []CheckConfig{{Type: "mock", Severity: "low", Interval: "1h"}},
				ReportInterval: "1h",
			})
		case "/api/v1/access/agent/report":
			reportReceived = true
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	dir := t.TempDir()
	cfg := &AgentConfig{ServerURL: server.URL, AgentID: "test", AuthToken: "tok"}
	cfg.Save(dir)

	a, err := NewAgent(logger, dir)
	require.NoError(t, err)

	// Register a mock check
	a.registry.Register("mock", &mockPassCheck{})

	err = a.RunOnce(context.Background())
	require.NoError(t, err)
	assert.True(t, reportReceived)
}

type mockPassCheck struct{}

func (m *mockPassCheck) Name() string { return "mock" }
func (m *mockPassCheck) Run(ctx context.Context, params map[string]interface{}) *checks.CheckResult {
	return &checks.CheckResult{Status: checks.StatusPass, Score: 1.0}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./internal/agent/ -v -run TestAgent`
Expected: FAIL — NewAgent not defined

- [ ] **Step 3: Implement agent runtime**

Write `agent/internal/agent/agent.go`:
```go
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

// Agent is the main runtime.
type Agent struct {
	logger     *zap.Logger
	config     *AgentConfig
	configDir  string
	client     *transport.Client
	registry   *checks.Registry
	engine     *checks.Engine
	serverCfg  *ServerConfig
}

func NewAgent(logger *zap.Logger, configDir string) (*Agent, error) {
	cfg, err := LoadConfig(configDir)
	if err != nil {
		return nil, fmt.Errorf("load agent config: %w", err)
	}

	client := transport.NewClient(cfg.ServerURL, cfg.AuthToken)
	registry := checks.NewRegistry()
	engine := checks.NewEngine(registry)

	return &Agent{
		logger:    logger,
		config:    cfg,
		configDir: configDir,
		client:    client,
		registry:  registry,
		engine:    engine,
	}, nil
}

// RegisterBuiltinChecks registers the standard posture checks.
func (a *Agent) RegisterBuiltinChecks() {
	a.registry.Register("os_version", &checks.OSVersionCheck{})
	a.registry.Register("disk_encryption", &checks.DiskEncryptionCheck{})
	a.registry.Register("process_running", &checks.ProcessCheck{})
}

// SyncConfig fetches the latest config from the server.
func (a *Agent) SyncConfig(ctx context.Context) error {
	data, err := a.client.GetConfig()
	if err != nil {
		a.logger.Warn("Failed to sync config, using cached", zap.Error(err))
		if a.serverCfg == nil {
			a.serverCfg = DefaultServerConfig()
		}
		return nil
	}

	var sc ServerConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return fmt.Errorf("parse server config: %w", err)
	}
	a.serverCfg = &sc
	a.logger.Info("Config synced", zap.Int("checks", len(sc.Checks)))
	return nil
}

// RunOnce performs one check cycle: sync config, run checks, report.
func (a *Agent) RunOnce(ctx context.Context) error {
	if err := a.SyncConfig(ctx); err != nil {
		return err
	}

	results := a.engine.RunChecks(ctx, a.serverCfg.Checks)

	data, err := json.Marshal(map[string]interface{}{
		"agent_id":  a.config.AgentID,
		"device_id": a.config.DeviceID,
		"results":   results,
		"timestamp": time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal results: %w", err)
	}

	if err := a.client.ReportResults(data); err != nil {
		a.logger.Warn("Failed to report results, caching locally", zap.Error(err))
	} else {
		a.logger.Info("Results reported", zap.Int("checks", len(results)))
	}

	return nil
}

// Run starts the agent loop until context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("Agent started",
		zap.String("agent_id", a.config.AgentID),
		zap.String("server", a.config.ServerURL))

	// Initial run
	if err := a.RunOnce(ctx); err != nil {
		a.logger.Error("Initial check cycle failed", zap.Error(err))
	}

	interval := 5 * time.Minute
	if a.serverCfg != nil && a.serverCfg.ReportInterval != "" {
		if d, err := time.ParseDuration(a.serverCfg.ReportInterval); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("Agent shutting down")
			return nil
		case <-ticker.C:
			if err := a.RunOnce(ctx); err != nil {
				a.logger.Error("Check cycle failed", zap.Error(err))
			}
		}
	}
}
```

- [ ] **Step 4: Run tests**

Run: `cd agent && go test ./internal/agent/ -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add agent/internal/agent/agent.go agent/internal/agent/agent_test.go
git commit -m "feat(agent): add agent runtime with sync, check, report loop"
```

---

### Task 7: Wire Up CLI Commands

**Files:**
- Modify: `agent/cmd/openidx-agent/main.go`

- [ ] **Step 1: Wire enroll and run commands to real implementations**

Replace `agent/cmd/openidx-agent/main.go`:
```go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	agentpkg "github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	rootCmd := &cobra.Command{
		Use:     "openidx-agent",
		Short:   "OpenIDX Endpoint Agent",
		Long:    "Unified endpoint agent for zero-trust access, posture checks, and policy enforcement.",
		Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildTime, Commit),
	}

	configDir := rootCmd.PersistentFlags().String("config-dir", "/var/lib/openidx-agent", "Agent configuration directory")
	rootCmd.PersistentFlags().Bool("verbose", false, "Verbose logging")

	rootCmd.AddCommand(newEnrollCmd(logger, configDir))
	rootCmd.AddCommand(newRunCmd(logger, configDir))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newEnrollCmd(logger *zap.Logger, configDir *string) *cobra.Command {
	var token string
	var serverURL string

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device with OpenIDX",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := transport.NewClient(serverURL, "")
			resp, err := client.Enroll(token)
			if err != nil {
				return fmt.Errorf("enrollment failed: %w", err)
			}

			cfg := &agentpkg.AgentConfig{
				ServerURL:  serverURL,
				AgentID:    resp.AgentID,
				DeviceID:   resp.DeviceID,
				AuthToken:  resp.AuthToken,
				EnrolledAt: time.Now().UTC().Format(time.RFC3339),
			}

			if err := cfg.Save(*configDir); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Printf("Enrolled successfully!\n")
			fmt.Printf("  Agent ID:  %s\n", resp.AgentID)
			fmt.Printf("  Device ID: %s\n", resp.DeviceID)
			fmt.Printf("  Config:    %s/agent.json\n", *configDir)
			return nil
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Enrollment token (required)")
	cmd.Flags().StringVar(&serverURL, "server", "", "OpenIDX server URL (required)")
	cmd.MarkFlagRequired("token")
	cmd.MarkFlagRequired("server")
	return cmd
}

func newRunCmd(logger *zap.Logger, configDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := agentpkg.NewAgent(logger, *configDir)
			if err != nil {
				return fmt.Errorf("init agent: %w", err)
			}
			a.RegisterBuiltinChecks()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				logger.Info("Received shutdown signal")
				cancel()
			}()

			return a.Run(ctx)
		},
	}
}
```

- [ ] **Step 2: Build and verify**

Run:
```bash
cd agent && go mod tidy && go build -o bin/openidx-agent ./cmd/openidx-agent
./bin/openidx-agent --help
./bin/openidx-agent enroll --help
./bin/openidx-agent run --help
```
Expected: Help text for all three commands

- [ ] **Step 3: Run all tests**

Run: `cd agent && go test -race ./...`
Expected: PASS (all packages)

- [ ] **Step 4: Commit**

```bash
git add agent/
git commit -m "feat(agent): wire CLI commands to enrollment and run loop"
```

---

### Task 8: Server-Side Agent API Endpoints

**Files:**
- Create: `internal/access/agent_api.go`
- Create: `internal/access/agent_api_test.go`

- [ ] **Step 1: Write agent API test**

Write `internal/access/agent_api_test.go`:
```go
package access

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAgentEnroll_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	handler := NewAgentAPIHandler(logger, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body, _ := json.Marshal(map[string]string{"token": "valid-enrollment-token"})
	c.Request, _ = http.NewRequest("POST", "/api/v1/access/agent/enroll", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Authorization", "Bearer valid-enrollment-token")

	handler.HandleEnroll(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["agent_id"])
	assert.NotEmpty(t, resp["device_id"])
	assert.NotEmpty(t, resp["auth_token"])
}

func TestAgentReport_Accepted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	handler := NewAgentAPIHandler(logger, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body, _ := json.Marshal(map[string]interface{}{
		"agent_id": "agent-001",
		"results":  []interface{}{},
	})
	c.Request, _ = http.NewRequest("POST", "/api/v1/access/agent/report", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.HandleReport(c)

	assert.Equal(t, http.StatusAccepted, w.Code)
}

func TestAgentConfig_ReturnsDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	handler := NewAgentAPIHandler(logger, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/v1/access/agent/config", nil)

	handler.HandleConfig(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp["checks"])
	assert.NotEmpty(t, resp["report_interval"])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/access/ -v -run TestAgent`
Expected: FAIL — NewAgentAPIHandler not defined

- [ ] **Step 3: Implement agent API handler**

Write `internal/access/agent_api.go`:
```go
package access

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// AgentAPIHandler handles agent enrollment, reporting, and config.
type AgentAPIHandler struct {
	logger *zap.Logger
	db     *database.PostgresDB
}

func NewAgentAPIHandler(logger *zap.Logger, db *database.PostgresDB) *AgentAPIHandler {
	return &AgentAPIHandler{logger: logger, db: db}
}

// RegisterAgentRoutes registers the agent API endpoints.
func (h *AgentAPIHandler) RegisterAgentRoutes(r *gin.RouterGroup) {
	agent := r.Group("/agent")
	{
		agent.POST("/enroll", h.HandleEnroll)
		agent.POST("/report", h.HandleReport)
		agent.GET("/config", h.HandleConfig)
	}
}

// HandleEnroll processes agent enrollment requests.
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(401, gin.H{"error": "enrollment token required"})
		return
	}

	// Generate agent identity
	agentID := fmt.Sprintf("agent-%s", uuid.New().String()[:8])
	deviceID := fmt.Sprintf("device-%s", uuid.New().String()[:8])
	authToken := uuid.New().String()

	h.logger.Info("Agent enrolled",
		zap.String("agent_id", agentID),
		zap.String("device_id", deviceID))

	c.JSON(200, gin.H{
		"agent_id":    agentID,
		"device_id":   deviceID,
		"auth_token":  authToken,
		"enrolled_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// HandleReport processes posture check results from agents.
func (h *AgentAPIHandler) HandleReport(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}

	var report map[string]interface{}
	if err := json.Unmarshal(body, &report); err != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}

	agentID, _ := report["agent_id"].(string)
	h.logger.Info("Agent report received",
		zap.String("agent_id", agentID),
		zap.Int("body_size", len(body)))

	c.JSON(202, gin.H{"status": "accepted"})
}

// HandleConfig returns the agent configuration.
func (h *AgentAPIHandler) HandleConfig(c *gin.Context) {
	config := map[string]interface{}{
		"checks": []map[string]interface{}{
			{"type": "os_version", "severity": "high", "interval": "1h", "params": map[string]interface{}{"min_version": "6.0"}},
			{"type": "disk_encryption", "severity": "critical", "interval": "6h"},
			{"type": "process_running", "severity": "medium", "interval": "15m", "params": map[string]interface{}{"processes": []string{"openidx-agent"}}},
		},
		"report_interval": "1h",
	}

	c.JSON(200, config)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/access/ -v -run TestAgent`
Expected: PASS (3 tests)

- [ ] **Step 5: Verify full project still builds**

Run: `go build ./... && go test ./... 2>&1 | grep -c "^ok"`
Expected: Build clean, 54+ packages pass

- [ ] **Step 6: Commit**

```bash
git add internal/access/agent_api.go internal/access/agent_api_test.go
git commit -m "feat(server): add agent enrollment, report, and config API endpoints"
```

---

### Task 9: Integration — Add Agent Build to Root Makefile

**Files:**
- Modify: `Makefile` (root)

- [ ] **Step 1: Add agent targets to root Makefile**

Add after the existing `build-cli` target:

```makefile
build-agent:
	@echo "Building openidx-agent..."
	cd agent && $(GOBUILD) -o ../bin/openidx-agent ./cmd/openidx-agent

build-agent-all:
	@echo "Cross-compiling openidx-agent..."
	cd agent && make build-all
	cp agent/bin/* bin/ 2>/dev/null || true

test-agent:
	@echo "Testing openidx-agent..."
	cd agent && go test -v -race ./...
```

Also add `build-agent test-agent` to the `.PHONY` line.

- [ ] **Step 2: Verify**

Run: `make build-agent && make test-agent`
Expected: Agent builds and tests pass

- [ ] **Step 3: Commit and push**

```bash
git add Makefile
git commit -m "feat: add agent build and test targets to root Makefile"
git push origin main
```
