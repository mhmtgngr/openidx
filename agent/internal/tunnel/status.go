// Package tunnel supervises the OpenZiti tunneler (ziti-edge-tunnel) that the
// OpenIDX agent bundles to replace the corporate VPN.
//
// The agent already holds a device identity on the overlay (dev-<agent_id>,
// written to ziti-identity.json at enrolment). The tunneler is what turns that
// identity into network access for every application on the device: it opens a
// TUN interface, answers DNS for the services the identity may dial, and
// carries their traffic over the overlay. The agent's job is to find the
// binary, hand it the identity, keep it running, and say how it is doing.
//
// What is decided here, and why:
//
//   - The tunneler runs as a CHILD of the agent on Windows (the agent service is
//     LocalSystem, which is what a TUN adapter needs) and on Linux when the
//     agent runs as root. One code path for start, restart and stop, its
//     lifetime is the agent's, and the service manager that already restarts
//     the agent (SCM failure actions, systemd Restart=always) covers the
//     tunneler with it. On Windows the child is placed in a job object that
//     kills it when the agent dies, so an agent crash never leaves an orphan
//     holding the IPC pipe and the TUN adapter for its successor to trip on.
//
//   - When the agent runs unprivileged on Linux (the shipped
//     openidx-agent.service runs as the openidx-agent user, which cannot open
//     a TUN device), the tunneler is the openidx-tunnel.service unit shipped
//     in the deb/rpm, and the agent runs in EXTERNAL mode: it writes the
//     identity and reads the status, and leaves the process to systemd. Mode
//     "auto" picks between the two by privilege.
//
//   - Health is read from the tunneler's own IPC by running
//     `ziti-edge-tunnel tunnel_status -P openidx`, which is the CLI's client
//     for the same command socket (a Unix socket under /tmp/.ziti, a named
//     pipe on Windows). Using the CLI rather than speaking the socket means
//     one implementation for both platforms and no dependency on the socket's
//     location, which the tunneler owns. The supervisor starts the tunneler
//     with the fixed IPC discriminator "openidx" (-P), so a second tunneler on
//     the same machine (Ziti Desktop Edge, say) cannot be confused with ours
//     and the status command never stops to ask which instance was meant.
//     When the IPC does not answer, process liveness plus an optional TCP dial
//     probe of an intercepted address stands in for it.
package tunnel

import "time"

// State is the tunnel's condition as the server and the tray see it.
type State string

const (
	// StateConnected: the tunneler is running and its identity is active on
	// the overlay.
	StateConnected State = "connected"
	// StateDegraded: the tunnel is meant to be on and is not fully working:
	// starting, restarting after a crash, an identity that is not loaded, an
	// IPC that does not answer, or no device identity to give it.
	StateDegraded State = "degraded"
	// StateOff: the tunnel is not enabled for this device.
	StateOff State = "off"
	// StateNotInstalled: the tunnel is enabled and no tunneler binary was
	// found (macOS today, or a package built without the bundle).
	StateNotInstalled State = "not_installed"
)

// Status is the tunnel's report, in exactly the shape the server stores as the
// agent report's tunnel_status object.
type Status struct {
	State State `json:"state"`
	// Version is the tunneler's own version, "" when it is not known.
	Version string `json:"version"`
	// LastSeen is when the tunneler last answered: its IPC replied, or the
	// dial probe connected. Nil when it never has.
	LastSeen *time.Time `json:"last_seen"`
	// Services are the names of the overlay services the tunneler intercepts
	// for this device, sorted. Never nil, so it is sent as [] and not null.
	Services []string `json:"services"`

	// The organization's tunnel policy as this device applied it. The
	// supervisor leaves these empty; the agent fills them from the policy it
	// last received (agent/internal/agent/tunnel.go), and they are omitted
	// until a server has sent one.
	//
	// Mode is "split" (only the overlay services are intercepted) or
	// "full". PolicyVersion is the version applied. PolicyGaps names what
	// the policy asks for that this device cannot enforce ("full_tunnel",
	// "block_direct"). LastError is why the tunnel, or applying the policy,
	// last failed.
	Mode          string   `json:"mode,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	PolicyGaps    []string `json:"policy_gaps,omitempty"`
	LastError     string   `json:"last_error,omitempty"`
}

// clone returns a copy whose slices and pointers the caller may keep.
func (s Status) clone() Status {
	out := s
	out.Services = append([]string{}, s.Services...)
	if s.PolicyGaps != nil {
		out.PolicyGaps = append([]string{}, s.PolicyGaps...)
	}
	if s.LastSeen != nil {
		t := *s.LastSeen
		out.LastSeen = &t
	}
	return out
}
