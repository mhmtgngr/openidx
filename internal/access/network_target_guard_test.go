package access

import (
	"net"
	"strings"
	"testing"
)

// pinTargetGuard replaces the host-derived guard with the configured part
// only (no interface addresses, no host name), so tests that use private
// addresses do not depend on the machine they run on.
func pinTargetGuard(t *testing.T) {
	t.Helper()
	orig := targetGuard
	targetGuard = func() *networkTargetGuard {
		g := orig()
		var deny []*net.IPNet
		for _, d := range g.deny {
			if ones, bits := d.Mask.Size(); ones == bits {
				continue // a host address: this machine's interfaces or platform hosts
			}
			deny = append(deny, d)
		}
		g.deny = deny
		return g
	}
	t.Cleanup(func() { targetGuard = orig })
}

func TestNetworkTargetRefusesThePlatform(t *testing.T) {
	pinTargetGuard(t)
	platformHostsMu.Lock()
	saved := platformHosts
	platformHostsMu.Unlock()
	t.Cleanup(func() {
		platformHostsMu.Lock()
		platformHosts = saved
		platformHostsMu.Unlock()
	})
	SetNetworkTargetPlatformHosts("https://ctrl.corp.example:1280")

	for name, tgt := range map[string]NetworkTarget{
		"loopback host":            {Hosts: []string{"127.0.0.1"}},
		"loopback v6":              {Hosts: []string{"::1"}},
		"metadata":                 {Hosts: []string{"169.254.169.254"}},
		"unspecified":              {Hosts: []string{"0.0.0.0"}},
		"multicast":                {Hosts: []string{"224.0.0.251"}},
		"loopback forward":         {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "127.0.0.1"},
		"metadata forward":         {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "169.254.169.254"},
		"localhost forward":        {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "localhost"},
		"localhost":                {Hosts: []string{"localhost"}},
		"sub.localhost":            {DNSNames: []string{"*.app.localhost"}},
		"controller by name":       {Hosts: []string{"ctrl.corp.example"}},
		"wildcard over controller": {DNSNames: []string{"*.corp.example"}},
		"CIDR over link-local":     {CIDRs: []string{"169.254.0.0/16"}},
		"CIDR over loopback":       {CIDRs: []string{"127.0.0.0/16"}},
		"CIDR broader than /16":    {CIDRs: []string{"10.0.0.0/8"}},
		"every address":            {CIDRs: []string{"0.0.0.0/0"}},
		"v6 broader than /48":      {CIDRs: []string{"2001:db8::/32"}},
		"podman network":           {CIDRs: []string{"10.89.0.0/24"}},
		"host in docker bridge":    {Hosts: []string{"172.17.0.2"}},
		"tunneler intercept range": {CIDRs: []string{"100.64.0.0/16"}},
	} {
		if _, err := normalizeNetworkTarget(tgt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// What a corporate network looks like is still accepted.
	for name, tgt := range map[string]NetworkTarget{
		"private /16":     {CIDRs: []string{"10.20.0.0/16"}},
		"host and domain": {Hosts: []string{"10.20.0.5", "fs1.corp.example"}, DNSNames: []string{"*.intranet.corp.example"}},
		"v6 /64":          {CIDRs: []string{"2001:db8:1:2::/64"}},
		"forward":         {CIDRs: []string{"10.30.0.0/24"}, ForwardAddress: "10.30.0.10", ForwardPort: 3389},
	} {
		if _, err := normalizeNetworkTarget(tgt); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestNetworkTargetGuardIsConfigurable(t *testing.T) {
	pinTargetGuard(t)
	t.Setenv("NETWORK_TARGET_MIN_PREFIX", "8")
	t.Setenv("NETWORK_TARGET_DENY_CIDRS", "192.168.50.0/24, 10.200.0.0/16")
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.0.0.0/8"}}); err == nil ||
		!strings.Contains(err.Error(), "10.200.0.0/16") {
		t.Errorf("a /8 overlapping a configured deny network: %v", err)
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"11.0.0.0/8"}}); err != nil {
		t.Errorf("NETWORK_TARGET_MIN_PREFIX=8 still refuses a /8: %v", err)
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"192.168.50.7"}}); err == nil {
		t.Error("a host inside NETWORK_TARGET_DENY_CIDRS was accepted")
	}
	// The configured list replaces the default platform networks; the
	// always-denied ones stay.
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.89.0.0/24"}}); err != nil {
		t.Errorf("the default list still applies when NETWORK_TARGET_DENY_CIDRS is set: %v", err)
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"169.254.169.254"}}); err == nil {
		t.Error("the metadata address is accepted once NETWORK_TARGET_DENY_CIDRS is set")
	}
}

// The real guard (not pinned) refuses this machine's own addresses.
func TestNetworkTargetRefusesThisHostsAddresses(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses: %v", err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{ipn.IP.String()}}); err == nil {
			t.Errorf("this host's address %s was accepted as a target", ipn.IP)
		}
		return
	}
	t.Skip("no non-loopback interface address on this machine")
}
