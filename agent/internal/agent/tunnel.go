package agent

import (
	"context"
	"encoding/json"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

// The bundled OpenZiti tunneler, supervised by the posture loop's process: the
// Windows service, or `openidx-agent run` under systemd. The tray's
// RemoteSupportOnly agent never starts one; it reads the service's status
// over the pipe instead.

// tunnelDir is where the tunneler's identity copy and log live.
func tunnelDir(configDir string) string { return filepath.Join(configDir, "tunnel") }

// tunnelSettings turns agent.json's "tunnel" object into the supervisor's
// configuration, and says whether the device's own setting turns the tunnel on.
//
// Every one of these settings is obeyed only when agent.json, AND the
// directory holding it, could have been written by nobody but the service and
// an administrator: binary_path and mode choose what this process runs with
// LocalSystem/root privileges, probe_address decides what counts as healthy,
// and enabled decides whether a privileged process starts at all. ConfigTrusted
// checks the file (Unix: not group/world-writable; Windows: owner and every ACE
// limited to SYSTEM, Administrators, TrustedInstaller); the directory is
// checked the same way, because whoever can write it can replace the file. A
// config that fails is not partly obeyed: the whole object is ignored and the
// tunnel stays off unless the organization's policy turns it on.
//
// What is never configurable, from any source: the arguments (fixed in
// internal/tunnel), the identity directory (under the config directory) and,
// whatever binary_path says, the trust check the binary itself must pass
// (internal/tunnel/locate.go). The server's org_network_policy only turns the
// tunnel on or off; it names no binary and no argument.
func (a *Agent) tunnelSettings() (cfg tunnel.Config, localEnabled bool) {
	cfg = tunnel.Config{
		Logger:         a.logger,
		AgentID:        a.config.AgentID,
		IdentitySource: a.config.ZitiIdentityFile,
		IdentityDir:    filepath.Join(tunnelDir(a.configDir), "identities"),
		LogFile:        filepath.Join(tunnelDir(a.configDir), "ziti-edge-tunnel.log"),
	}
	tc := a.config.Tunnel
	if tc == nil {
		return cfg, false
	}
	if err := tunnelConfigTrusted(a.configDir); err != nil {
		a.logger.Error("ignoring agent.json's tunnel settings: agent.json could have been written by "+
			"an account this service does not trust", zap.Error(err))
		return cfg, false
	}
	cfg.BinaryPath = tc.BinaryPath
	cfg.Mode = tunnel.Mode(tc.Mode)
	cfg.ProbeAddress = tc.ProbeAddress
	return cfg, tc.Enabled
}

// tunnelConfigTrusted is ConfigTrusted plus the same check on the directory
// that holds agent.json.
func tunnelConfigTrusted(configDir string) error {
	if err := ConfigTrusted(configDir); err != nil {
		return err
	}
	return plugin.CheckTrustedPath(configDir)
}

// newTunnelSupervisor builds the supervisor from tunnelSettings.
func (a *Agent) newTunnelSupervisor() *tunnel.Supervisor {
	cfg, local := a.tunnelSettings()
	a.tunLocalOn.Store(local)
	return tunnel.New(cfg)
}

// startTunnel creates the supervisor and runs it until ctx ends. It is called
// once, by Run.
func (a *Agent) startTunnel(ctx context.Context) {
	s := a.newTunnelSupervisor()
	a.tun.Store(s)
	a.applyTunnelEnablement()
	a.logger.Info("tunnel supervisor ready", zap.String("mode", string(s.Mode())),
		zap.Bool("enabled", s.Enabled()))
	go func() {
		if err := s.Run(ctx); err != nil && err != context.Canceled {
			a.logger.Error("tunnel supervisor stopped", zap.Error(err))
		}
	}()
}

// applyTunnelEnablement turns the tunnel on when a trusted agent.json enables
// it or the organization's policy makes it always on.
func (a *Agent) applyTunnelEnablement() {
	s := a.tun.Load()
	if s == nil {
		return
	}
	s.SetEnabled(a.tunLocalOn.Load() || a.orgAlwaysOn.Load())
}

// applyNetworkPolicy records the server's org_network_policy. A policy that
// does not mention always_on leaves the last known value alone.
func (a *Agent) applyNetworkPolicy(p *OrgNetworkPolicy) {
	if p == nil || p.AlwaysOn == nil {
		return
	}
	if a.orgAlwaysOn.Swap(*p.AlwaysOn) != *p.AlwaysOn {
		a.logger.Info("organization network policy", zap.Bool("always_on", *p.AlwaysOn))
	}
	a.applyTunnelEnablement()
}

// applyReportResponse reads org_network_policy from a report response, when
// the server sends one there. Anything else in the response is ignored, and a
// response that is not JSON is not an error: older servers answer {"status":..}.
func (a *Agent) applyReportResponse(body []byte) {
	if len(body) == 0 {
		return
	}
	var resp struct {
		OrgNetworkPolicy *OrgNetworkPolicy `json:"org_network_policy"`
	}
	if json.Unmarshal(body, &resp) == nil {
		a.applyNetworkPolicy(resp.OrgNetworkPolicy)
	}
}

// TunnelStatus is the tunnel's state for the report and the tray, or nil when
// this process supervises no tunnel (the tray's agent, or before Run).
func (a *Agent) TunnelStatus() *tunnel.Status {
	s := a.tun.Load()
	if s == nil {
		return nil
	}
	st := s.Status()
	return &st
}

// TunnelDetail says why the tunnel is in its state, for the tray.
func (a *Agent) TunnelDetail() string {
	if s := a.tun.Load(); s != nil {
		return s.Detail()
	}
	return ""
}
