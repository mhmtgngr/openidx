package doctor

import (
	"context"
	"time"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

// unownedTunnelAddr is an address inside the tunneler's default range
// (100.64.0.0/10) that the tunneler never uses: it owns .1 (the interface) and
// .2 (its DNS) and hands out the rest to names, in order from the bottom.
const unownedTunnelAddr = "100.64.0.77:53"

// probeName is a name that cannot exist (RFC 6761), so no real resolver has a
// reason to answer it with anything but "no such name".
const probeName = "openidx-probe.invalid"

// namesProbeTimeout is short on purpose: a clean device times out, and that is
// the answer we want.
var namesProbeTimeout = 1500 * time.Millisecond

// checkNames asks whether something other than the tunnel is answering DNS
// meant for the tunnel. It sends one question to an address nobody on the
// device owns. Nothing legitimate answers there, so any reply means a driver
// is answering UDP/53 for every destination. VPN clients that enforce DNS do
// this (GlobalProtect answered NXDOMAIN to 8.8.8.8, to 192.168.1.1 and to the
// tunnel's own resolver alike), and then names of tunneled applications never
// reach the tunneler. Addresses are unaffected, so this is a warning, not a
// failure.
func checkNames(ctx context.Context, p Probes, in Inputs) Check {
	c := Check{ID: CheckNames, Status: StatusPass}
	switch {
	case in.Mobile:
		c.Status, c.Detail = StatusSkipped, "the app is the engine"
	case in.Tunnel == nil || in.Tunnel.State != tunnel.StateConnected:
		c.Status, c.Detail = StatusSkipped, "tunnel not connected"
	default:
		ctx, cancel := context.WithTimeout(ctx, namesProbeTimeout)
		defer cancel()
		if ans, err := p.DNSQuery(ctx, unownedTunnelAddr, probeName); err == nil {
			c.Status, c.Code = StatusWarn, CodeDNSIntercepted
			c.Detail = "an address nobody owns answered a DNS question"
			_ = ans
		}
	}
	return c
}
