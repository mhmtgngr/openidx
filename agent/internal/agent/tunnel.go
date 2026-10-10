package agent

import (
	"context"
	"encoding/json"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

// The bundled OpenZiti tunneler, supervised by the posture loop's process: the
// Windows service, or `openidx-agent run` under systemd. The tray's
// RemoteSupportOnly agent never starts one; it reads the service's status
// over the pipe instead.

// tunnelDir is where the tunneler's identity copy and log live.
func tunnelDir(configDir string) string { return filepath.Join(configDir, "tunnel") }

// newTunnelSupervisor builds the supervisor from agent.json. binary_path and
// a non-default mode choose what this process runs with its privileges, so,
// like plugin_dir, they are obeyed only from a config file nobody but the
// service and an administrator could have written.
func (a *Agent) newTunnelSupervisor() *tunnel.Supervisor {
	cfg := tunnel.Config{
		Logger:         a.logger,
		AgentID:        a.config.AgentID,
		IdentitySource: a.config.ZitiIdentityFile,
		IdentityDir:    filepath.Join(tunnelDir(a.configDir), "identities"),
		LogFile:        filepath.Join(tunnelDir(a.configDir), "ziti-edge-tunnel.log"),
	}
	if tc := a.config.Tunnel; tc != nil {
		cfg.ProbeAddress = tc.ProbeAddress
		if tc.BinaryPath != "" || tc.Mode != "" {
			if err := ConfigTrusted(a.configDir); err != nil {
				a.logger.Error("ignoring tunnel.binary_path and tunnel.mode: agent.json could have been "+
					"written by an account this service does not trust", zap.Error(err))
			} else {
				cfg.BinaryPath = tc.BinaryPath
				cfg.Mode = tunnel.Mode(tc.Mode)
			}
		}
	}
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

// applyTunnelEnablement turns the tunnel on when agent.json enables it or the
// organization's policy makes it always on.
func (a *Agent) applyTunnelEnablement() {
	s := a.tun.Load()
	if s == nil {
		return
	}
	local := a.config.Tunnel != nil && a.config.Tunnel.Enabled
	s.SetEnabled(local || a.orgAlwaysOn.Load())
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
