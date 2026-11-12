package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/secretfile"
	"github.com/openidx/openidx/agent/internal/transport"
)

// Fleet commands (Faz B8.6). The server hands the service its queued
// commands in /agent/config, each once; the service runs them in order and
// answers each through POST /agent/commands/:id/result. Only a process that
// sets RunCommands asks for them (the service, or a foreground "run"): the
// tray syncs with the same credential and must not take them.

// Command is one fleet command as /agent/config delivers it.
type Command struct {
	ID   string          `json:"id"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args,omitempty"`
}

// CommandHooks are the platform's half of the commands. A nil hook makes
// its command fail with "not supported here".
type CommandHooks struct {
	// Restart ends the process so its service manager starts it again. Called
	// after the result is sent.
	Restart func()
	// UpdateNow asks the update loop for an immediate check.
	UpdateNow func()
	// Uninstall starts a detached removal of the product. Called after the
	// result is sent; an error before then is reported instead.
	Uninstall func() error
	// LogFiles names the log files collect_logs gathers, besides the
	// tunneler's.
	LogFiles func() []string
	// SetLogLevel applies a new log level to the running process.
	SetLogLevel func(level string)
}

// commandOptions is set_options' arguments.
type commandOptions struct {
	LogLevel      *string `json:"log_level,omitempty"`
	TrayHidden    *bool   `json:"tray_hidden,omitempty"`
	TunnelEnabled *bool   `json:"tunnel_enabled,omitempty"`
}

// commandOutcome is a command's result before it is sent.
type commandOutcome struct {
	status       string
	result       map[string]any
	artifact     []byte
	artifactName string
	after        func()
}

const (
	// maxLogArtifactBytes is the server's cap on an artifact.
	maxLogArtifactBytes = 8 << 20
	// maxLogFileTail is how much of each log file is kept: the end of it.
	maxLogFileTail = 3 << 20
)

// runCommands runs each delivered command in order and answers it.
func (a *Agent) runCommands(cmds []Command) {
	for _, c := range cmds {
		if c.ID == "" {
			continue
		}
		a.handledCommandsMu.Lock()
		if a.handledCommands == nil {
			a.handledCommands = map[string]bool{}
		}
		seen := a.handledCommands[c.ID]
		a.handledCommands[c.ID] = true
		a.handledCommandsMu.Unlock()
		if seen {
			continue
		}
		out := a.runCommand(c)
		if err := a.sendCommandResult(c.ID, out); err != nil {
			a.logger.Warn("could not answer a fleet command", zap.String("command", c.ID),
				zap.String("kind", c.Kind), zap.Error(err))
		} else {
			a.logger.Info("fleet command answered", zap.String("command", c.ID),
				zap.String("kind", c.Kind), zap.String("status", out.status))
		}
		if out.after != nil {
			out.after()
		}
	}
}

func failed(err string) commandOutcome {
	return commandOutcome{status: "failed", result: map[string]any{"error": err}}
}

func (a *Agent) runCommand(c Command) commandOutcome {
	h := a.CommandHooks
	switch c.Kind {
	case "restart":
		if h.Restart == nil {
			return failed("restart is not supported here")
		}
		return commandOutcome{status: "done", result: map[string]any{"message": "restarting"}, after: h.Restart}
	case "update_now":
		if h.UpdateNow == nil {
			return failed("updates are not run by this process")
		}
		h.UpdateNow()
		return commandOutcome{status: "done", result: map[string]any{"message": "update check started"}}
	case "uninstall":
		if h.Uninstall == nil {
			return failed("uninstall is not supported here")
		}
		return commandOutcome{status: "done", result: map[string]any{"message": "uninstalling"}, after: func() {
			if err := h.Uninstall(); err != nil {
				a.logger.Error("uninstall failed to start", zap.Error(err))
			}
		}}
	case "reenroll":
		if LoadSealedToken(a.configDir) == "" {
			return failed("this device holds no sealed enrollment token")
		}
		if !a.reenrolFromSealedToken() {
			return failed("re-enrolling with the sealed token failed; see the agent log")
		}
		return commandOutcome{status: "done", result: map[string]any{"agent_id": a.config.AgentID}}
	case "set_options":
		return a.setOptions(c.Args)
	case "collect_logs":
		data, files, err := CollectLogs(a.configDir, a.logFiles())
		if err != nil {
			return failed(err.Error())
		}
		name := "openidx-logs-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
		return commandOutcome{status: "done", result: map[string]any{"files": files, "bytes": len(data)},
			artifact: data, artifactName: name}
	}
	return failed("unknown command kind " + c.Kind)
}

func (a *Agent) logFiles() []string {
	var files []string
	if a.CommandHooks.LogFiles != nil {
		files = append(files, a.CommandHooks.LogFiles()...)
	}
	return append(files, filepath.Join(tunnelDir(a.configDir), "ziti-edge-tunnel.log"))
}

// setOptions applies set_options and stores what persists in agent.json.
func (a *Agent) setOptions(raw json.RawMessage) commandOutcome {
	var o commandOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		return failed("set_options arguments are not readable")
	}
	cfg, err := LoadConfig(a.configDir)
	if err != nil || cfg == nil {
		return failed("agent.json could not be read")
	}
	applied := map[string]any{}
	if o.LogLevel != nil {
		cfg.LogLevel = *o.LogLevel
		if a.CommandHooks.SetLogLevel != nil {
			a.CommandHooks.SetLogLevel(*o.LogLevel)
		}
		applied["log_level"] = *o.LogLevel
	}
	if o.TrayHidden != nil {
		cfg.TrayHidden = *o.TrayHidden
		applied["tray_hidden"] = *o.TrayHidden
	}
	if o.TunnelEnabled != nil {
		if cfg.Tunnel == nil {
			cfg.Tunnel = &TunnelConfig{}
		}
		cfg.Tunnel.Enabled = *o.TunnelEnabled
		a.tunLocalOn.Store(*o.TunnelEnabled)
		a.applyTunnelEnablement()
		applied["tunnel_enabled"] = *o.TunnelEnabled
	}
	if err := cfg.Save(a.configDir); err != nil {
		return failed("agent.json could not be saved: " + err.Error())
	}
	if a.config != nil {
		a.config.LogLevel, a.config.TrayHidden, a.config.Tunnel = cfg.LogLevel, cfg.TrayHidden, cfg.Tunnel
	}
	return commandOutcome{status: "done", result: map[string]any{"applied": applied}}
}

func (a *Agent) sendCommandResult(id string, out commandOutcome) error {
	cr, ok := a.client.(transport.CommandResponder)
	if !ok {
		return errors.New("this transport cannot answer commands")
	}
	body := map[string]any{"status": out.status, "result": out.result}
	if out.artifact != nil {
		body["artifact_b64"] = base64.StdEncoding.EncodeToString(out.artifact)
		body["artifact_name"] = out.artifactName
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return cr.SendCommandResult(id, data)
}

// redactedKeys are agent.json's secrets, replaced in a log bundle.
var redactedKeys = []string{"auth_token", "push_enroll_token"}

// CollectLogs gathers the end of each log file that exists and agent.json
// with its secrets replaced, as a tar.gz of at most 8 MiB. It returns the
// archive and the names it holds.
func CollectLogs(configDir string, logFiles []string) ([]byte, []string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	var names []string
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		names = append(names, name)
		return err
	}
	if raw, err := secretfile.Read(ConfigPath(configDir)); err == nil {
		red, err := redactConfig(raw)
		if err != nil {
			red = []byte("agent.json could not be parsed, so it is left out\n")
		}
		if err := add("agent.json", red); err != nil {
			return nil, nil, err
		}
	}
	seen := map[string]bool{}
	for _, f := range logFiles {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		data, err := tailFile(f, maxLogFileTail)
		if err != nil {
			continue
		}
		if err := add(filepath.Base(f), data); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	if buf.Len() > maxLogArtifactBytes {
		return nil, nil, fmt.Errorf("the log bundle is %d bytes, over the 8 MiB limit", buf.Len())
	}
	return buf.Bytes(), names, nil
}

// redactConfig replaces agent.json's secrets with "[redacted]".
func redactConfig(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for _, k := range redactedKeys {
		if v, ok := m[k]; ok && v != "" {
			m[k] = "[redacted]"
		}
	}
	return json.MarshalIndent(m, "", "  ")
}

// tailFile reads at most max bytes from the end of path.
func tailFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a log file this agent writes
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, max))
}
