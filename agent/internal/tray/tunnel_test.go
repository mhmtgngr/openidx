package tray

import (
	"fmt"
	"testing"

	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

func tst(s tunnel.State, detail string, svcs ...string) *ipc.Status {
	return &ipc.Status{TunnelDetail: detail, Tunnel: &tunnel.Status{State: s, Services: svcs}}
}

func TestTunnelTitle(t *testing.T) {
	cases := []struct {
		st   *ipc.Status
		want string
	}{
		{nil, ""},
		{&ipc.Status{}, ""},
		{tst(tunnel.StateConnected, ""), "Network: Connected"},
		{tst(tunnel.StateConnected, "", "erp"), "Network: Connected · 1 service"},
		{tst(tunnel.StateConnected, "", "erp", "rdp"), "Network: Connected · 2 services"},
		{tst(tunnel.StateDegraded, ""), "Network: Connecting…"},
		{tst(tunnel.StateDegraded, "the tunneler is starting"), "Network: Connecting…"},
		{tst(tunnel.StateDegraded, "the tunneler exited. restarting"), "Network: Error · the tunneler exited"},
		{tst(tunnel.StateOff, ""), "Network: Off"},
		{tst(tunnel.StateNotInstalled, ""), "Network: Error · tunnel not installed"},
	}
	for _, c := range cases {
		if got := tunnelTitle(c.st, &enStrings); got != c.want {
			t.Errorf("tunnelTitle(%+v) = %q, want %q", c.st, got, c.want)
		}
	}
	if got := tunnelTitle(tst(tunnel.StateOff, ""), &trStrings); got != "Ağ: Kapalı" {
		t.Errorf("tr off = %q", got)
	}
}

func TestTunnelStateReasonIsShort(t *testing.T) {
	long := "identity could not be loaded because the enrolment file is missing from disk entirely"
	s, r := tunnelState(tst(tunnel.StateDegraded, long), &enStrings)
	if s != netError || len([]rune(r)) > maxReasonLen {
		t.Errorf("state %v reason %q", s, r)
	}
}

func TestTunnelLines(t *testing.T) {
	if got := tunnelLines(tst(tunnel.StateConnected, "", "erp", "rdp"), &enStrings); fmt.Sprint(got) != "[erp rdp]" {
		t.Errorf("connected lines = %v", got)
	}
	got := tunnelLines(tst(tunnel.StateDegraded, "the tunneler exited", "erp"), &enStrings)
	if fmt.Sprint(got) != "[the tunneler exited erp]" {
		t.Errorf("degraded lines = %v, want the reason first", got)
	}
	if got := tunnelLines(tst(tunnel.StateOff, ""), &enStrings); len(got) != 1 || got[0] != enStrings.NetOffHint {
		t.Errorf("off lines = %v, want the IT hint", got)
	}
	if got := tunnelLines(tst(tunnel.StateOff, ""), &trStrings); got[0] != trStrings.NetOffHint {
		t.Errorf("tr off lines = %v", got)
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("svc-%02d", i))
	}
	got = tunnelLines(tst(tunnel.StateConnected, "", many...), &enStrings)
	if len(got) != maxTunnelSlots || got[len(got)-1] != "…and 26 more" {
		t.Errorf("40 services: %d lines ending %q", len(got), got[len(got)-1])
	}
}
