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
// (internal/tunnel/locate.go). The server's org_network_policy turns the
// tunnel on or off and gives the ranges the direct-access block covers, which
// are parsed as prefixes before they reach nft; it names no binary and no
// argument.
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
	a.directBlock.Store(tunnel.NewDirectBlock())
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

// applyNetworkPolicy records the server's org_network_policy and enforces
// what this device can of it. A policy that does not mention always_on
// leaves the last known value alone; one without a version (a server older
// than the rest of the policy) is read for always_on only.
//
// What each switch does here:
//
//   - always_on: the tunnel is enabled whatever agent.json says, and the
//     supervisor restarts the tunneler whenever it exits (with backoff). There
//     is no user-facing way to disconnect: the tray shows the tunnel and
//     offers no off switch, and agent.json, which only an administrator can
//     write, cannot turn off what the policy turned on.
//   - split_tunnel: the bundled tunneler (ziti-edge-tunnel) intercepts only
//     the addresses of the overlay services this device may dial, so the
//     device always runs split. A policy asking for a full tunnel is
//     reported as the gap "full_tunnel" rather than claimed.
//   - block_direct_corporate_cidrs: loaded into the firewall where the
//     platform has a hook (internal/tunnel/directblock.go, Linux as root);
//     elsewhere reported as the gap "block_direct".
//
// The version is reported back as applied only when nothing failed; gaps do
// not hold it back (they are what the device can do, and say so), an error
// does, and the next policy delivery tries again.
func (a *Agent) applyNetworkPolicy(p *OrgNetworkPolicy) {
	if p == nil {
		return
	}
	if p.AlwaysOn != nil {
		if a.orgAlwaysOn.Swap(*p.AlwaysOn) != *p.AlwaysOn {
			a.logger.Info("organization network policy", zap.Bool("always_on", *p.AlwaysOn))
		}
		a.applyTunnelEnablement()
	}
	if p.Version == "" {
		return
	}
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	prev := a.netPolicy.Load()
	if prev != nil && prev.policy.Version == p.Version && prev.err == "" && prev.enforcer == a.directBlock.Load() {
		return
	}
	cp := *p
	cp.CorporateCIDRs = append([]string(nil), p.CorporateCIDRs...)
	ap := a.enforceNetworkPolicy(cp, prev)
	a.netPolicy.Store(ap)
	a.logger.Info("organization network policy applied", zap.String("version", ap.policy.Version),
		zap.String("mode", ap.mode), zap.Strings("gaps", ap.gaps), zap.String("error", ap.err))
}

// appliedPolicy is a versioned org_network_policy and what this device made
// of it.
type appliedPolicy struct {
	policy OrgNetworkPolicy
	mode   string   // "split": see applyNetworkPolicy
	gaps   []string // what the policy asks for and this device cannot enforce
	err    string   // why applying it failed; "" when it did not
	// enforcer is the DirectBlock it was applied with; nil in a process that
	// supervises no tunnel. A policy applied before startTunnel is applied
	// again once there is one.
	enforcer *tunnel.DirectBlock
	blocking bool // the block is loaded
}

// enforceNetworkPolicy applies p; prev is the policy applied before, if any.
func (a *Agent) enforceNetworkPolicy(p OrgNetworkPolicy, prev *appliedPolicy) *appliedPolicy {
	d := a.directBlock.Load()
	ap := &appliedPolicy{policy: p, mode: "split", enforcer: d}
	if p.SplitTunnel != nil && !*p.SplitTunnel {
		ap.gaps = append(ap.gaps, "full_tunnel")
	}
	block := p.BlockDirectCorporateCIDRs != nil && *p.BlockDirectCorporateCIDRs
	if d == nil {
		// The tray's agent, or before Run: this process never touches the
		// firewall. What it would not enforce is still said.
		if block {
			ap.gaps = append(ap.gaps, "block_direct")
		}
		return ap
	}
	if err := d.Supported(); err != nil {
		if block {
			ap.gaps = append(ap.gaps, "block_direct")
			a.logger.Warn("the organization's policy blocks direct corporate access; this device cannot enforce it",
				zap.Error(err))
		}
		return ap
	}
	switch {
	case block:
		if err := d.Apply(p.CorporateCIDRs); err != nil {
			ap.err = err.Error()
			a.logger.Error("blocking direct corporate access failed", zap.Error(err))
			return ap
		}
		ap.blocking = len(p.CorporateCIDRs) > 0
	case prev == nil || prev.enforcer != d || prev.blocking || prev.err != "":
		// The first policy this process applies also removes a block an
		// earlier run left behind when the policy has since turned it off.
		if err := d.Clear(); err != nil {
			ap.err = err.Error()
			a.logger.Error("removing the direct corporate access block failed", zap.Error(err))
		}
	}
	return ap
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
	if ap := a.netPolicy.Load(); ap != nil {
		st.Mode = ap.mode
		if ap.err == "" {
			st.PolicyVersion = ap.policy.Version
		}
		st.PolicyGaps = append([]string(nil), ap.gaps...)
		st.LastError = ap.err
	}
	if st.LastError == "" && (st.State == tunnel.StateDegraded || st.State == tunnel.StateNotInstalled) {
		st.LastError = s.Detail()
	}
	return &st
}

// TunnelDetail says why the tunnel is in its state, for the tray.
func (a *Agent) TunnelDetail() string {
	if s := a.tun.Load(); s != nil {
		return s.Detail()
	}
	return ""
}
