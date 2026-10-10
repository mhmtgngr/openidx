package tray

import (
	"fmt"

	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

// maxTunnelSlots bounds the Network submenu.
const maxTunnelSlots = 15

// tunnelTitle is the Network menu item's title, or "" to hide the item: the
// service did not answer, or it supervises no tunnel (an older agent).
func tunnelTitle(st *ipc.Status) string {
	if st == nil || st.Tunnel == nil {
		return ""
	}
	switch st.Tunnel.State {
	case tunnel.StateConnected:
		switch n := len(st.Tunnel.Services); n {
		case 0:
			return "Network: Connected"
		case 1:
			return "Network: Connected · 1 service"
		default:
			return fmt.Sprintf("Network: Connected · %d services", n)
		}
	case tunnel.StateDegraded:
		return "Network: Degraded"
	case tunnel.StateNotInstalled:
		return "Network: Not installed"
	}
	return "Network: Off"
}

// tunnelLines are the Network submenu's lines: why the tunnel is not
// connected, then the services it intercepts, at most maxTunnelSlots in all.
func tunnelLines(st *ipc.Status) []string {
	if st == nil || st.Tunnel == nil {
		return nil
	}
	var lines []string
	switch st.Tunnel.State {
	case tunnel.StateOff:
		return []string{"The network tunnel is off for this device"}
	case tunnel.StateDegraded, tunnel.StateNotInstalled:
		if st.TunnelDetail != "" {
			lines = append(lines, st.TunnelDetail)
		}
	}
	lines = append(lines, st.Tunnel.Services...)
	if len(lines) > maxTunnelSlots {
		more := len(lines) - (maxTunnelSlots - 1)
		lines = append(lines[:maxTunnelSlots-1], fmt.Sprintf("…and %d more", more))
	}
	return lines
}
