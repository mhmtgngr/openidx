package tray

import (
	"fmt"
	"strings"

	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

// maxTunnelSlots bounds the Network submenu.
const maxTunnelSlots = 15

// maxReasonLen keeps the status line's reason short enough for a menu.
const maxReasonLen = 48

// netState is the one-word condition a first-time user understands.
type netState int

const (
	netHidden netState = iota
	netConnected
	netConnecting
	netOff
	netError
)

// tunnelState maps the service's tunnel report to what the tray says, with
// a short reason for Error. Degraded with no detail, or a detail about
// starting, is still Connecting; anything else degraded is an Error.
func tunnelState(st *ipc.Status, s *strs) (netState, string) {
	if st == nil || st.Tunnel == nil {
		return netHidden, ""
	}
	switch st.Tunnel.State {
	case tunnel.StateConnected:
		return netConnected, ""
	case tunnel.StateOff:
		return netOff, ""
	case tunnel.StateNotInstalled:
		return netError, s.NetNotInstalled
	}
	d := strings.TrimSpace(st.TunnelDetail)
	if d == "" {
		return netConnecting, ""
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(d), func(r rune) bool {
		return r == ' ' || r == '.' || r == ',' || r == ':'
	}) {
		if w == "starting" || w == "connecting" {
			return netConnecting, ""
		}
	}
	return netError, shorten(d)
}

func shorten(s string) string {
	if i := strings.IndexAny(s, "\n.;"); i > 0 {
		s = s[:i]
	}
	r := []rune(s)
	if len(r) > maxReasonLen {
		s = string(r[:maxReasonLen-1]) + "…"
	}
	return s
}

// tunnelTitle is the Network menu item's one-line status, or "" to hide the
// item: the service did not answer, or it supervises no tunnel.
func tunnelTitle(st *ipc.Status, s *strs) string {
	state, reason := tunnelState(st, s)
	head := s.Network + ": "
	switch state {
	case netConnected:
		switch n := len(st.Tunnel.Services); n {
		case 0:
			return head + s.NetConnected
		case 1:
			return head + s.NetConnected + " · " + s.NetServiceOne
		default:
			return head + s.NetConnected + " · " + fmt.Sprintf(s.NetServicesN, n)
		}
	case netConnecting:
		return head + s.NetConnecting + "…"
	case netOff:
		return head + s.NetOff
	case netError:
		if reason != "" {
			return head + s.NetError + " · " + reason
		}
		return head + s.NetError
	}
	return ""
}

// tunnelLines are the Network submenu's lines: why the tunnel is not
// connected (who turns it on, when off by policy), then the services it
// intercepts, at most maxTunnelSlots in all.
func tunnelLines(st *ipc.Status, s *strs) []string {
	if st == nil || st.Tunnel == nil {
		return nil
	}
	var lines []string
	switch st.Tunnel.State {
	case tunnel.StateOff:
		return []string{s.NetOffHint}
	case tunnel.StateDegraded, tunnel.StateNotInstalled:
		if st.TunnelDetail != "" {
			lines = append(lines, st.TunnelDetail)
		}
	}
	lines = append(lines, st.Tunnel.Services...)
	if len(lines) > maxTunnelSlots {
		more := len(lines) - (maxTunnelSlots - 1)
		lines = append(lines[:maxTunnelSlots-1], fmt.Sprintf(s.NetMore, more))
	}
	return lines
}
