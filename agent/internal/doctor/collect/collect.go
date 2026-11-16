// Package collect runs the doctor against this device: it gathers what the
// device knows about itself (agent.json when this account may read it, the
// service's status pipe when it answers) and hands it to the checks. The CLI,
// the tray and the control engine all diagnose through it, so they agree.
package collect

import (
	"context"
	"runtime"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/transport"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

// Deps are the seams of a run.
type Deps struct {
	LoadConfig func(dir string) (*agent.AgentConfig, error)
	QueryIPC   func() (*ipc.Status, error)
	Probes     doctor.Probes
	Actions    doctor.Actions
	// Settle is how long to wait after a repair before checking again.
	Settle time.Duration
}

// DefaultDeps diagnoses the real device.
func DefaultDeps() Deps {
	return Deps{
		LoadConfig: agent.LoadConfig,
		QueryIPC:   ipc.Query,
		Probes:     doctor.NewProbes(),
		Actions:    doctor.NewActions(),
		Settle:     8 * time.Second,
	}
}

// Inputs collects what the device knows about itself.
func Inputs(d Deps, dir, version string) doctor.Inputs {
	in := doctor.Inputs{AgentVersion: version}

	cfg, err := d.LoadConfig(dir)
	if err == nil {
		in.AgentID = cfg.AgentID
		in.ServerURL = cfg.ServerURL
		in.ProxyURL = cfg.ProxyURL
		in.Enrolled = cfg.AgentID != ""
		in.IdentityFile = cfg.ZitiIdentityFile
		in.TunnelExpected = cfg.Tunnel != nil && cfg.Tunnel.Enabled
		// Probe the way the agent connects: same proxy, same server CA.
		_ = transport.SetNetworkOptions(cfg.NetworkOptions())
	} else {
		in.ConfigErr = err
	}

	st, qerr := d.QueryIPC()
	switch {
	case qerr == nil && st != nil:
		running := true
		in.ServiceRunning = &running
		in.AuthInvalid, in.Revoked, in.Tunnel = st.AuthInvalid, st.Revoked, st.Tunnel
		if st.Tunnel != nil {
			in.TunnelExpected = in.TunnelExpected || st.Tunnel.State != tunnel.StateOff
		}
		if err != nil {
			// The service can read what this account cannot.
			in.AgentID, in.ServerURL, in.Enrolled = st.AgentID, st.ServerURL, st.Enrolled
			in.ConfigErr = nil
		}
	case runtime.GOOS != "windows":
		// No status pipe on this platform: the service's state is unknown.
	default:
		running := false
		in.ServiceRunning = &running
	}
	return in
}

// Run diagnoses the device. With fix it applies the safe repairs and, when
// one took, checks again; without, the bundle lists what --fix would try.
func Run(ctx context.Context, d Deps, dir, version string, fix bool) doctor.Bundle {
	if ctx == nil {
		ctx = context.Background()
	}
	b := doctor.Run(ctx, Inputs(d, dir, version), d.Probes, doctor.Options{})
	if !fix {
		b.Repairs = doctor.PlanRepairs(b)
		return b
	}
	repairs := doctor.ApplyRepairs(ctx, b, d.Actions)
	for _, r := range repairs {
		if r.Outcome == doctor.OutcomeApplied {
			select {
			case <-ctx.Done():
			case <-time.After(d.Settle):
			}
			b = doctor.Run(ctx, Inputs(d, dir, version), d.Probes, doctor.Options{})
			break
		}
	}
	b.Repairs = repairs
	return b
}
