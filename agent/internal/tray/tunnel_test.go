package tray

import (
	"fmt"
	"testing"

	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

func TestTunnelTitle(t *testing.T) {
	st := func(s tunnel.State, svcs ...string) *ipc.Status {
		return &ipc.Status{Tunnel: &tunnel.Status{State: s, Services: svcs}}
	}
	cases := []struct {
		st   *ipc.Status
		want string
	}{
		{nil, ""},
		{&ipc.Status{}, ""},
		{st(tunnel.StateConnected), "Network: Connected"},
		{st(tunnel.StateConnected, "erp"), "Network: Connected · 1 service"},
		{st(tunnel.StateConnected, "erp", "rdp"), "Network: Connected · 2 services"},
		{st(tunnel.StateDegraded), "Network: Degraded"},
		{st(tunnel.StateOff), "Network: Off"},
		{st(tunnel.StateNotInstalled), "Network: Not installed"},
	}
	for _, c := range cases {
		if got := tunnelTitle(c.st); got != c.want {
			t.Errorf("tunnelTitle(%+v) = %q, want %q", c.st, got, c.want)
		}
	}
}

func TestTunnelLines(t *testing.T) {
	if got := tunnelLines(&ipc.Status{Tunnel: &tunnel.Status{State: tunnel.StateConnected,
		Services: []string{"erp", "rdp"}}}); fmt.Sprint(got) != "[erp rdp]" {
		t.Errorf("connected lines = %v", got)
	}
	got := tunnelLines(&ipc.Status{TunnelDetail: "the tunneler exited", Tunnel: &tunnel.Status{
		State: tunnel.StateDegraded, Services: []string{"erp"}}})
	if fmt.Sprint(got) != "[the tunneler exited erp]" {
		t.Errorf("degraded lines = %v, want the reason first", got)
	}
	if got := tunnelLines(&ipc.Status{Tunnel: &tunnel.Status{State: tunnel.StateOff}}); len(got) != 1 {
		t.Errorf("off lines = %v", got)
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("svc-%02d", i))
	}
	got = tunnelLines(&ipc.Status{Tunnel: &tunnel.Status{State: tunnel.StateConnected, Services: many}})
	if len(got) != maxTunnelSlots || got[len(got)-1] != "…and 26 more" {
		t.Errorf("40 services: %d lines ending %q", len(got), got[len(got)-1])
	}
}
