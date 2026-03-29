# Agent Plugin Runtime — Phase 2b Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add plugin runtime that discovers, loads, and runs external check plugins via JSON-over-stdin/stdout protocol.

**Architecture:** Plugin discovery scans a directory for executables with manifest.json. Each plugin is wrapped as a `Check` implementation and registered in the existing Registry. The engine runs plugins the same way it runs built-in checks.

**Tech Stack:** Go 1.25, os/exec, encoding/json

---

## File Structure

```
agent/
├── internal/
│   ├── plugin/
│   │   ├── manifest.go          # Manifest model + LoadManifest
│   │   ├── manifest_test.go     # Manifest tests
│   │   ├── protocol.go          # Request/Response structs + Execute
│   │   ├── protocol_test.go     # Protocol tests
│   │   ├── check.go             # PluginCheck (implements checks.Check)
│   │   ├── check_test.go        # PluginCheck tests
│   │   ├── loader.go            # Loader: Discover()
│   │   └── loader_test.go       # Loader tests
│   └── agent/
│       ├── agent.go             # Modified: call LoadPlugins after RegisterBuiltinChecks
│       └── config.go            # Modified: add PluginDir to AgentConfig
└── plugins/
    └── plugin-hello/
        ├── manifest.json        # Example plugin manifest
        └── hello-check.sh       # Example plugin executable
```

---

## Task 1: Plugin Manifest Model

**Files to create:**
- `agent/internal/plugin/manifest.go`
- `agent/internal/plugin/manifest_test.go`

### Step 1: Write failing tests

```go
// agent/internal/plugin/manifest_test.go
package plugin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	m := plugin.Manifest{
		Name:           "hello-check",
		Version:        "1.0.0",
		Description:    "A hello world check plugin",
		Platforms:      []string{"linux", "darwin"},
		CheckTypes:     []string{"hello"},
		Schedule:       "1h",
		TimeoutSeconds: 30,
	}
	data, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644))

	got, err := plugin.LoadManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, "hello-check", got.Name)
	assert.Equal(t, "1.0.0", got.Version)
	assert.Equal(t, []string{"linux", "darwin"}, got.Platforms)
	assert.Equal(t, []string{"hello"}, got.CheckTypes)
	assert.Equal(t, 30, got.TimeoutSeconds)
}

func TestLoadManifest_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := plugin.LoadManifest(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading manifest")
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{bad json"), 0644))

	_, err := plugin.LoadManifest(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing manifest")
}

func TestManifest_DefaultTimeout(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"name":"minimal","version":"0.1.0","check_types":["foo"]}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644))

	got, err := plugin.LoadManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, 0, got.TimeoutSeconds) // caller should apply default
}
```

### Step 2: Implement manifest.go

```go
// agent/internal/plugin/manifest.go
package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest describes a plugin's identity, capabilities, and runtime requirements.
// It is read from manifest.json in the plugin directory.
type Manifest struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description,omitempty"`
	Platforms      []string `json:"platforms,omitempty"`
	CheckTypes     []string `json:"check_types"`
	Schedule       string   `json:"schedule,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// LoadManifest reads and parses manifest.json from dir.
func LoadManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, "manifest.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest from %s: %w", path, err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest from %s: %w", path, err)
	}

	return &m, nil
}
```

### Step 3: Run tests

```bash
cd /home/cmit/openidx/agent && go test ./internal/plugin/ -run TestLoadManifest -v
```

### Commit message

```
feat(agent/plugin): add Manifest model and LoadManifest
```

---

## Task 2: Plugin Protocol

**Files to create:**
- `agent/internal/plugin/protocol.go`
- `agent/internal/plugin/protocol_test.go`

### Step 1: Write failing tests

```go
// agent/internal/plugin/protocol_test.go
package plugin_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildEchoPlugin compiles a tiny Go program that reads a JSON request from
// stdin and writes a canned JSON response to stdout. Returns the binary path.
func buildEchoPlugin(t *testing.T, response plugin.Response) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("plugin protocol tests require a Unix shell")
	}

	respJSON, err := json.Marshal(response)
	require.NoError(t, err)

	src := `package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	io.ReadAll(os.Stdin)
	fmt.Fprintf(os.Stdout, ` + "`%s`" + `, string(` + "`" + string(respJSON) + "`" + `))
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))

	bin := filepath.Join(dir, "plugin-echo")
	cmd := exec.Command("go", "build", "-o", bin, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build output: %s", out)
	return bin
}

func TestExecute_Success(t *testing.T) {
	want := plugin.Response{
		Status:  "pass",
		Score:   1.0,
		Message: "all good",
		Details: map[string]interface{}{"key": "value"},
	}
	bin := buildEchoPlugin(t, want)

	req := &plugin.Request{Action: "check", Type: "hello", Params: nil}
	got, err := plugin.Execute(context.Background(), bin, req, 10*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "pass", got.Status)
	assert.InDelta(t, 1.0, got.Score, 0.001)
	assert.Equal(t, "all good", got.Message)
}

func TestExecute_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix")
	}
	// A plugin that sleeps forever.
	src := `package main
import "time"
func main() { time.Sleep(10 * time.Minute) }
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))
	bin := filepath.Join(dir, "plugin-sleep")
	cmd := exec.Command("go", "build", "-o", bin, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build output: %s", out)

	req := &plugin.Request{Action: "check", Type: "hello"}
	_, err = plugin.Execute(context.Background(), bin, req, 100*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestExecute_InvalidJSONResponse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix")
	}
	src := `package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	io.ReadAll(os.Stdin)
	fmt.Fprintln(os.Stdout, "not valid json at all")
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))
	bin := filepath.Join(dir, "plugin-badjson")
	cmd := exec.Command("go", "build", "-o", bin, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build output: %s", out)

	req := &plugin.Request{Action: "check", Type: "hello"}
	_, err = plugin.Execute(context.Background(), bin, req, 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding plugin response")
}
```

### Step 2: Implement protocol.go

```go
// agent/internal/plugin/protocol.go
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Request is the JSON payload written to the plugin's stdin.
type Request struct {
	Action string                 `json:"action"`
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Response is the JSON payload read from the plugin's stdout.
type Response struct {
	Status      string                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}

// Execute starts execPath as a subprocess, writes req as JSON to its stdin,
// and reads a Response from its stdout. The process is killed if it has not
// exited before timeout elapses.
func Execute(ctx context.Context, execPath string, req *Request, timeout time.Duration) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding plugin request: %w", err)
	}

	cmd := exec.CommandContext(ctx, execPath)
	cmd.Stdin = bytes.NewReader(reqData)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("plugin %s timed out after %s", execPath, timeout)
		}
		return nil, fmt.Errorf("running plugin %s: %w", execPath, err)
	}

	var resp Response
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("decoding plugin response from %s: %w", execPath, err)
	}

	return &resp, nil
}
```

### Step 3: Run tests

```bash
cd /home/cmit/openidx/agent && go test ./internal/plugin/ -run TestExecute -v
```

### Commit message

```
feat(agent/plugin): add JSON-over-stdin/stdout protocol with timeout
```

---

## Task 3: Plugin Check Adapter

**Files to create:**
- `agent/internal/plugin/check.go`
- `agent/internal/plugin/check_test.go`

### Step 1: Write failing tests

```go
// agent/internal/plugin/check_test.go
package plugin_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildResponsePlugin compiles a plugin binary that returns the given Response.
func buildResponsePlugin(t *testing.T, resp plugin.Response) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix")
	}
	respJSON, err := json.Marshal(resp)
	require.NoError(t, err)

	src := `package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	io.ReadAll(os.Stdin)
	fmt.Fprint(os.Stdout, ` + "`" + string(respJSON) + "`" + `)
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))
	bin := filepath.Join(dir, "plugin")
	cmd := exec.Command("go", "build", "-o", bin, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build: %s", out)
	return bin
}

func TestPluginCheck_ImplementsCheckInterface(t *testing.T) {
	m := &plugin.Manifest{Name: "hello-check", TimeoutSeconds: 10}
	pc := plugin.NewPluginCheck(m, "/usr/bin/true")
	var _ checks.Check = pc // compile-time assertion
	assert.Equal(t, "hello-check", pc.Name())
}

func TestPluginCheck_Run_Pass(t *testing.T) {
	resp := plugin.Response{Status: "pass", Score: 1.0, Message: "ok"}
	bin := buildResponsePlugin(t, resp)

	m := &plugin.Manifest{Name: "hello-check", TimeoutSeconds: 10}
	pc := plugin.NewPluginCheck(m, bin)

	result := pc.Run(context.Background(), nil)
	assert.Equal(t, checks.StatusPass, result.Status)
	assert.InDelta(t, 1.0, result.Score, 0.001)
	assert.Equal(t, "ok", result.Message)
}

func TestPluginCheck_Run_Fail(t *testing.T) {
	resp := plugin.Response{Status: "fail", Score: 0.0, Message: "failed", Remediation: "fix it"}
	bin := buildResponsePlugin(t, resp)

	m := &plugin.Manifest{Name: "fail-check", TimeoutSeconds: 10}
	pc := plugin.NewPluginCheck(m, bin)

	result := pc.Run(context.Background(), nil)
	assert.Equal(t, checks.StatusFail, result.Status)
	assert.Equal(t, "fix it", result.Remediation)
}

func TestPluginCheck_Run_Warn(t *testing.T) {
	resp := plugin.Response{Status: "warn", Score: 0.5}
	bin := buildResponsePlugin(t, resp)

	m := &plugin.Manifest{Name: "warn-check", TimeoutSeconds: 10}
	pc := plugin.NewPluginCheck(m, bin)

	result := pc.Run(context.Background(), nil)
	assert.Equal(t, checks.StatusWarn, result.Status)
}

func TestPluginCheck_Run_ExecutionError(t *testing.T) {
	m := &plugin.Manifest{Name: "bad-check", TimeoutSeconds: 1}
	pc := plugin.NewPluginCheck(m, "/nonexistent/plugin-binary")

	result := pc.Run(context.Background(), nil)
	assert.Equal(t, checks.StatusError, result.Status)
	assert.NotEmpty(t, result.Message)
}

func TestPluginCheck_Run_DefaultTimeout(t *testing.T) {
	// TimeoutSeconds==0 should use a sensible default (30s), not block forever.
	resp := plugin.Response{Status: "pass", Score: 1.0}
	bin := buildResponsePlugin(t, resp)

	m := &plugin.Manifest{Name: "notimeout-check", TimeoutSeconds: 0}
	pc := plugin.NewPluginCheck(m, bin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := pc.Run(ctx, nil)
	assert.Equal(t, checks.StatusPass, result.Status)
}
```

### Step 2: Implement check.go

```go
// agent/internal/plugin/check.go
package plugin

import (
	"context"
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
)

const defaultTimeoutSeconds = 30

// PluginCheck wraps an external plugin executable as a checks.Check.
type PluginCheck struct {
	manifest *Manifest
	execPath string
}

// NewPluginCheck returns a PluginCheck that runs execPath for the given manifest.
func NewPluginCheck(manifest *Manifest, execPath string) *PluginCheck {
	return &PluginCheck{manifest: manifest, execPath: execPath}
}

// Name returns the plugin's name from its manifest.
func (p *PluginCheck) Name() string {
	return p.manifest.Name
}

// Run invokes the plugin executable with action="check" and converts the
// response into a checks.CheckResult.
func (p *PluginCheck) Run(ctx context.Context, params map[string]interface{}) *checks.CheckResult {
	timeout := time.Duration(p.manifest.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultTimeoutSeconds * time.Second
	}

	req := &Request{
		Action: "check",
		Type:   p.manifest.Name,
		Params: params,
	}

	resp, err := Execute(ctx, p.execPath, req, timeout)
	if err != nil {
		return &checks.CheckResult{
			Status:  checks.StatusError,
			Message: err.Error(),
		}
	}

	return &checks.CheckResult{
		Status:      mapStatus(resp.Status),
		Score:       resp.Score,
		Details:     resp.Details,
		Message:     resp.Message,
		Remediation: resp.Remediation,
	}
}

// mapStatus converts the plugin's string status to a checks.Status constant.
// Unknown values are treated as StatusError.
func mapStatus(s string) checks.Status {
	switch checks.Status(s) {
	case checks.StatusPass, checks.StatusFail, checks.StatusWarn, checks.StatusError:
		return checks.Status(s)
	default:
		return checks.StatusError
	}
}
```

### Step 3: Run tests

```bash
cd /home/cmit/openidx/agent && go test ./internal/plugin/ -run TestPluginCheck -v
```

### Commit message

```
feat(agent/plugin): add PluginCheck adapter implementing checks.Check
```

---

## Task 4: Plugin Discovery and Loader

**Files to create:**
- `agent/internal/plugin/loader.go`
- `agent/internal/plugin/loader_test.go`

### Step 1: Write failing tests

```go
// agent/internal/plugin/loader_test.go
package plugin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func writeManifest(t *testing.T, dir string, m plugin.Manifest) {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644))
}

func writeFakeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	bin := filepath.Join(dir, name)
	// Write a minimal shell script so os.Stat sees an executable.
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755))
	return bin
}

func TestLoader_Discover_SinglePlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("platform filter uses 'linux'/'darwin'")
	}
	pluginDir := t.TempDir()
	pdir := filepath.Join(pluginDir, "hello-check")
	require.NoError(t, os.MkdirAll(pdir, 0755))

	currentPlatform := runtime.GOOS
	writeManifest(t, pdir, plugin.Manifest{
		Name:           "hello-check",
		Version:        "1.0.0",
		Platforms:      []string{currentPlatform},
		CheckTypes:     []string{"hello"},
		TimeoutSeconds: 10,
	})
	writeFakeExecutable(t, pdir, "hello-check")

	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)
	plugins, err := loader.Discover()
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	assert.Equal(t, "hello-check", plugins[0].Name())
}

func TestLoader_Discover_FiltersByPlatform(t *testing.T) {
	pluginDir := t.TempDir()
	pdir := filepath.Join(pluginDir, "win-only")
	require.NoError(t, os.MkdirAll(pdir, 0755))

	writeManifest(t, pdir, plugin.Manifest{
		Name:       "win-only",
		Version:    "1.0.0",
		Platforms:  []string{"windows"},
		CheckTypes: []string{"win-check"},
	})
	writeFakeExecutable(t, pdir, "win-only")

	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)

	if runtime.GOOS != "windows" {
		plugins, err := loader.Discover()
		require.NoError(t, err)
		assert.Empty(t, plugins, "platform-filtered plugin should not be returned on non-Windows")
	}
}

func TestLoader_Discover_SkipsDirWithNoManifest(t *testing.T) {
	pluginDir := t.TempDir()
	pdir := filepath.Join(pluginDir, "incomplete-plugin")
	require.NoError(t, os.MkdirAll(pdir, 0755))
	// No manifest.json, just an executable.
	writeFakeExecutable(t, pdir, "incomplete-plugin")

	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Empty(t, plugins)
}

func TestLoader_Discover_SkipsDirWithNoExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable detection is Unix-centric")
	}
	pluginDir := t.TempDir()
	pdir := filepath.Join(pluginDir, "no-exec")
	require.NoError(t, os.MkdirAll(pdir, 0755))

	writeManifest(t, pdir, plugin.Manifest{
		Name:       "no-exec",
		Version:    "1.0.0",
		Platforms:  []string{runtime.GOOS},
		CheckTypes: []string{"no-exec"},
	})
	// Manifest exists but no executable file.

	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Empty(t, plugins)
}

func TestLoader_Discover_EmptyDir(t *testing.T) {
	pluginDir := t.TempDir()
	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Empty(t, plugins)
}

func TestLoader_Discover_MultiplePlugins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix")
	}
	pluginDir := t.TempDir()
	currentPlatform := runtime.GOOS

	for _, name := range []string{"plugin-a", "plugin-b"} {
		pdir := filepath.Join(pluginDir, name)
		require.NoError(t, os.MkdirAll(pdir, 0755))
		writeManifest(t, pdir, plugin.Manifest{
			Name:       name,
			Version:    "1.0.0",
			Platforms:  []string{currentPlatform},
			CheckTypes: []string{name},
		})
		writeFakeExecutable(t, pdir, name)
	}

	logger := zap.NewNop()
	loader := plugin.NewLoader(pluginDir, logger)
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Len(t, plugins, 2)
}
```

### Step 2: Implement loader.go

```go
// agent/internal/plugin/loader.go
package plugin

import (
	"os"
	"path/filepath"
	"runtime"

	"go.uber.org/zap"
)

// Loader discovers plugin executables in a directory and returns PluginCheck
// instances for each valid, platform-compatible plugin found.
type Loader struct {
	pluginDir string
	logger    *zap.Logger
}

// NewLoader returns a Loader that scans pluginDir.
func NewLoader(pluginDir string, logger *zap.Logger) *Loader {
	return &Loader{pluginDir: pluginDir, logger: logger}
}

// Discover scans pluginDir for subdirectories that contain a manifest.json and
// a matching executable. It skips plugins that do not support the current
// platform (runtime.GOOS). An empty or non-existent pluginDir is not an error.
func (l *Loader) Discover() ([]*PluginCheck, error) {
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var plugins []*PluginCheck

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pdir := filepath.Join(l.pluginDir, entry.Name())
		pc, err := l.loadPlugin(pdir)
		if err != nil {
			l.logger.Warn("skipping plugin directory",
				zap.String("dir", pdir),
				zap.Error(err),
			)
			continue
		}
		if pc == nil {
			continue // filtered (e.g. wrong platform)
		}
		plugins = append(plugins, pc)
	}

	return plugins, nil
}

// loadPlugin attempts to load a single plugin from dir. It returns nil (with no
// error) when the plugin is intentionally skipped (e.g. wrong platform).
func (l *Loader) loadPlugin(dir string) (*PluginCheck, error) {
	manifest, err := LoadManifest(dir)
	if err != nil {
		return nil, err
	}

	// Filter by platform if the manifest declares supported platforms.
	if !platformSupported(manifest.Platforms) {
		l.logger.Debug("skipping plugin: platform not supported",
			zap.String("plugin", manifest.Name),
			zap.Strings("platforms", manifest.Platforms),
			zap.String("current", runtime.GOOS),
		)
		return nil, nil
	}

	execPath := filepath.Join(dir, manifest.Name)
	info, err := os.Stat(execPath)
	if err != nil {
		return nil, err
	}
	// Require the file to be executable (Unix permission bit).
	if info.Mode()&0111 == 0 {
		return nil, os.ErrPermission
	}

	l.logger.Info("discovered plugin",
		zap.String("name", manifest.Name),
		zap.String("version", manifest.Version),
	)

	return NewPluginCheck(manifest, execPath), nil
}

// platformSupported returns true when platforms is empty (meaning all platforms)
// or when runtime.GOOS appears in the list.
func platformSupported(platforms []string) bool {
	if len(platforms) == 0 {
		return true
	}
	current := runtime.GOOS
	for _, p := range platforms {
		if p == current {
			return true
		}
	}
	return false
}
```

### Step 3: Run tests

```bash
cd /home/cmit/openidx/agent && go test ./internal/plugin/ -run TestLoader -v
```

### Commit message

```
feat(agent/plugin): add Loader with platform-aware plugin discovery
```

---

## Task 5: Integrate Plugins into Agent Runtime

**Files to create/modify:**
- Modify: `agent/internal/agent/agent.go` — add `LoadPlugins` method, call it after `RegisterBuiltinChecks`
- Modify: `agent/internal/agent/config.go` — add `PluginDir` to `AgentConfig`
- Create: `agent/plugins/plugin-hello/manifest.json`
- Create: `agent/plugins/plugin-hello/hello-check.sh`
- Create/update: `agent/internal/agent/agent_test.go` (plugin integration test)

### Step 1: Write failing tests

Add to `agent/internal/agent/agent_test.go`:

```go
// TestAgent_LoadPlugins_RegistersPluginChecks tests that LoadPlugins discovers
// plugins from the configured PluginDir and registers them in the registry.
func TestAgent_LoadPlugins_RegistersPluginChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix")
	}

	// Build a minimal check plugin binary.
	respJSON := `{"status":"pass","score":1.0,"message":"hello from plugin"}`
	src := fmt.Sprintf(`package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	io.ReadAll(os.Stdin)
	fmt.Fprint(os.Stdout, %q)
}
`, respJSON)

	buildDir := t.TempDir()
	srcFile := filepath.Join(buildDir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))

	pluginDir := t.TempDir()
	pdir := filepath.Join(pluginDir, "hello-check")
	require.NoError(t, os.MkdirAll(pdir, 0755))

	// Build the binary directly into the plugin subdir with the plugin's name.
	bin := filepath.Join(pdir, "hello-check")
	cmd := exec.Command("go", "build", "-o", bin, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build output: %s", out)

	manifest := map[string]interface{}{
		"name":            "hello-check",
		"version":         "1.0.0",
		"platforms":       []string{runtime.GOOS},
		"check_types":     []string{"hello"},
		"timeout_seconds": 10,
	}
	mdata, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(pdir, "manifest.json"), mdata, 0644))

	// Bootstrap a minimal agent config.
	cfgDir := t.TempDir()
	agentCfg := agent.AgentConfig{
		ServerURL: "http://localhost:0",
		AgentID:   "test-agent",
		DeviceID:  "test-device",
		PluginDir: pluginDir,
	}
	data, err := json.Marshal(agentCfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "agent.json"), data, 0644))

	logger := zap.NewNop()
	a, err := agent.NewAgent(logger, cfgDir)
	require.NoError(t, err)

	a.RegisterBuiltinChecks()
	require.NoError(t, a.LoadPlugins())

	names := a.Registry().List()
	assert.Contains(t, names, "hello-check")
}
```

### Step 2: Modify config.go — add PluginDir

```go
// AgentConfig holds the persisted configuration for a registered agent.
type AgentConfig struct {
	ServerURL  string `json:"server_url"`
	AgentID    string `json:"agent_id"`
	DeviceID   string `json:"device_id"`
	EnrolledAt string `json:"enrolled_at"`
	AuthToken  string `json:"auth_token,omitempty"`
	PluginDir  string `json:"plugin_dir,omitempty"`
}
```

### Step 3: Modify agent.go — add LoadPlugins and expose Registry

Add two methods to the `Agent` struct in `agent/internal/agent/agent.go`:

```go
// Registry returns the agent's check registry. Exposed for testing.
func (a *Agent) Registry() *checks.Registry {
	return a.registry
}

// LoadPlugins uses a plugin.Loader to discover external check plugins in the
// configured PluginDir and registers each as a Check in the registry. A missing
// or empty PluginDir is silently ignored.
func (a *Agent) LoadPlugins() error {
	pluginDir := a.config.PluginDir
	if pluginDir == "" {
		pluginDir = "/etc/openidx-agent/plugins"
	}

	loader := plugin.NewLoader(pluginDir, a.logger)
	discovered, err := loader.Discover()
	if err != nil {
		return fmt.Errorf("discovering plugins: %w", err)
	}

	for _, pc := range discovered {
		a.registry.Register(pc.Name(), pc)
		a.logger.Info("registered plugin check", zap.String("name", pc.Name()))
	}

	a.logger.Info("plugin loading complete", zap.Int("count", len(discovered)))
	return nil
}
```

Also update the import block in `agent.go` to include:

```go
"github.com/openidx/openidx/agent/internal/plugin"
```

And update `NewAgent` to call `LoadPlugins` is NOT automatic — the caller is
responsible for calling both `RegisterBuiltinChecks` and `LoadPlugins` after
construction, keeping them composable. The `Run` method does not change; it
already relies on the registry being populated before `Run` is called. Document
this in the `NewAgent` godoc:

```go
// NewAgent loads the persisted agent config from configDir, creates a transport
// client, and initialises an empty check registry and engine.
// Callers should invoke RegisterBuiltinChecks and LoadPlugins before calling Run.
```

### Step 4: Create example plugin

```json
// agent/plugins/plugin-hello/manifest.json
{
  "name": "hello-check",
  "version": "1.0.0",
  "description": "Example plugin that always reports pass",
  "platforms": ["linux", "darwin"],
  "check_types": ["hello"],
  "schedule": "1h",
  "timeout_seconds": 10
}
```

```bash
#!/bin/sh
# agent/plugins/plugin-hello/hello-check.sh
# Example OpenIDX agent plugin.
# Reads a JSON request from stdin; writes a JSON response to stdout.
#
# Actions:
#   check     — run the check and report status
#   info      — return plugin metadata
#   remediate — attempt automated remediation (no-op here)

set -e

INPUT=$(cat)
ACTION=$(printf '%s' "$INPUT" | grep -o '"action":"[^"]*"' | head -1 | cut -d'"' -f4)

case "$ACTION" in
  check)
    printf '{"status":"pass","score":1.0,"message":"Hello from plugin-hello","details":{"platform":"%s"}}\n' "$(uname -s | tr '[:upper:]' '[:lower:]')"
    ;;
  info)
    printf '{"status":"pass","score":1.0,"message":"hello-check v1.0.0","details":{"check_types":["hello"]}}\n'
    ;;
  remediate)
    printf '{"status":"pass","score":1.0,"message":"no remediation needed"}\n'
    ;;
  *)
    printf '{"status":"error","score":0,"message":"unknown action: %s"}\n' "$ACTION"
    exit 1
    ;;
esac
```

Make the script executable:

```bash
chmod +x /home/cmit/openidx/agent/plugins/plugin-hello/hello-check.sh
```

### Step 5: Run all plugin tests

```bash
cd /home/cmit/openidx/agent && go test ./internal/plugin/... ./internal/agent/... -v
```

### Step 6: Run full agent test suite

```bash
cd /home/cmit/openidx/agent && go test ./... -v
```

### Commit message

```
feat(agent): integrate plugin runtime — LoadPlugins registers external checks
```

---

## Verification Checklist

- [ ] `go test ./internal/plugin/...` passes (all 4 test files)
- [ ] `go test ./internal/agent/...` passes including `TestAgent_LoadPlugins_RegistersPluginChecks`
- [ ] `go vet ./...` reports no issues
- [ ] `agent/plugins/plugin-hello/hello-check.sh` is executable and responds correctly:
  ```bash
  echo '{"action":"check","type":"hello"}' | sh agent/plugins/plugin-hello/hello-check.sh
  # expected: {"status":"pass","score":1.0,...}
  ```
- [ ] `AgentConfig.PluginDir` round-trips through JSON marshal/unmarshal
- [ ] Missing `PluginDir` defaults to `/etc/openidx-agent/plugins` without error

---

## Design Notes

**Why separate `plugin` package?** Keeps protocol, discovery, and adapter logic isolated from `checks` and `agent` packages, enabling independent testing of each layer without standing up a full agent.

**Why not auto-call `LoadPlugins` in `NewAgent`?** Startup order matters: built-in checks should register first. Keeping both calls explicit in the caller (e.g., `main.go`) preserves composability and makes testing easier — a test can skip plugin loading entirely.

**Timeout precedence:** `manifest.TimeoutSeconds` is the primary timeout. If it is 0 (omitted), `PluginCheck.Run` falls back to 30 seconds. The parent context deadline (if tighter) always wins because `Execute` uses `context.WithTimeout` which inherits existing deadlines.

**Platform filter:** An empty `platforms` list in the manifest means "all platforms" to allow generic plugins. A non-empty list must include `runtime.GOOS` for the plugin to be loaded.

**Executable naming convention:** The executable inside the plugin directory must match `manifest.name`. This keeps discovery simple and unambiguous without extra fields in the manifest.
