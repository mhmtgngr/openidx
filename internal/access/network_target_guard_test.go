package access

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// pinTargetGuard replaces the host-derived guard with the configured part
// only (no interface addresses, no host name), so tests that use private
// addresses do not depend on the machine they run on.
func pinTargetGuard(t *testing.T) {
	t.Helper()
	orig := targetGuard
	targetGuard = func() *networkTargetGuard {
		g := orig()
		var deny []netip.Prefix
		for _, d := range g.deny {
			if d.Bits() == d.Addr().BitLen() && !d.Addr().IsLoopback() && d.Addr() != netip.MustParseAddr("fd00:ec2::254") && !d.Addr().IsUnspecified() {
				continue // a host address: this machine's interfaces or platform hosts
			}
			deny = append(deny, d)
		}
		g.deny = deny
		return g
	}
	t.Cleanup(func() { targetGuard = orig })
}

func withPlatformHosts(t *testing.T, hosts ...string) {
	t.Helper()
	platformHostsMu.Lock()
	saved := platformHosts
	platformHostsMu.Unlock()
	t.Cleanup(func() {
		platformHostsMu.Lock()
		platformHosts = saved
		platformHostsMu.Unlock()
	})
	SetNetworkTargetPlatformHosts(hosts...)
}

func TestNetworkTargetRefusesThePlatform(t *testing.T) {
	pinTargetGuard(t)
	withPlatformHosts(t, "https://ctrl.corp.example:1280")

	for name, tgt := range map[string]NetworkTarget{
		// The ranges.
		"loopback host":            {Hosts: []string{"127.0.0.1"}},
		"loopback v6":              {Hosts: []string{"::1"}},
		"metadata":                 {Hosts: []string{"169.254.169.254"}},
		"aws v6 metadata":          {Hosts: []string{"fd00:ec2::254"}},
		"unspecified":              {Hosts: []string{"0.0.0.0"}},
		"unspecified v6":           {Hosts: []string{"::"}},
		"this network":             {Hosts: []string{"0.1.2.3"}},
		"multicast":                {Hosts: []string{"224.0.0.251"}},
		"multicast v6":             {Hosts: []string{"ff02::1"}},
		"link-local v6":            {Hosts: []string{"fe80::1"}},
		"broadcast":                {Hosts: []string{"255.255.255.255"}},
		"reserved 240/4":           {Hosts: []string{"240.0.0.1"}},
		"IETF 192.0.0/24":          {Hosts: []string{"192.0.0.8"}},
		"benchmarking 198.18/15":   {CIDRs: []string{"198.18.0.0/16"}},
		"loopback forward":         {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "127.0.0.1"},
		"metadata forward":         {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "169.254.169.254"},
		"localhost forward":        {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "localhost"},
		"CIDR over link-local":     {CIDRs: []string{"169.254.0.0/16"}},
		"CIDR over loopback":       {CIDRs: []string{"127.0.0.0/16"}},
		"CIDR broader than /16":    {CIDRs: []string{"10.0.0.0/8"}},
		"every address":            {CIDRs: []string{"0.0.0.0/0"}},
		"v6 broader than /48":      {CIDRs: []string{"2001:db8::/32"}},
		"podman network":           {CIDRs: []string{"10.89.0.0/24"}},
		"host in docker bridge":    {Hosts: []string{"172.17.0.2"}},
		"tunneler intercept range": {CIDRs: []string{"100.64.0.0/16"}},

		// Spellings another parser might read as a denied address.
		"mapped v6 loopback":       {Hosts: []string{"::ffff:127.0.0.1"}},
		"mapped v6 metadata":       {Hosts: []string{"::ffff:169.254.169.254"}},
		"mapped v6 hex":            {Hosts: []string{"::ffff:7f00:1"}},
		"mapped v6 CIDR":           {CIDRs: []string{"::ffff:127.0.0.0/120"}},
		"NAT64 loopback":           {Hosts: []string{"64:ff9b::127.0.0.1"}},
		"NAT64 metadata":           {Hosts: []string{"64:ff9b::a9fe:a9fe"}},
		"NAT64 local-use":          {Hosts: []string{"64:ff9b:1::7f00:1"}},
		"6to4 loopback":            {Hosts: []string{"2002:7f00:1::1"}},
		"6to4 metadata":            {Hosts: []string{"2002:a9fe:a9fe::1"}},
		"CIDR over NAT64":          {CIDRs: []string{"64:ff9b::/96"}},
		"CIDR over 6to4":           {CIDRs: []string{"2002:a00::/24"}},
		"short form 127.1":         {Hosts: []string{"127.1"}},
		"decimal 2130706433":       {Hosts: []string{"2130706433"}},
		"hex 0x7f.1":               {Hosts: []string{"0x7f.1"}},
		"hex 0x7f000001":           {Hosts: []string{"0x7f000001"}},
		"octal 0177.0.0.1":         {Hosts: []string{"0177.0.0.1"}},
		"octal forward":            {Hosts: []string{"fs1.corp.example"}, ForwardAddress: "0177.0.0.1"},
		"trailing dot IP":          {Hosts: []string{"127.0.0.1."}},
		"zone id":                  {Hosts: []string{"fe80::1%eth0"}},
		"zone id 2":                {Hosts: []string{"2001:db8::1%25eth0"}},
		"percent-encoded":          {Hosts: []string{"127%2e0%2e0%2e1"}},
		"inner whitespace":         {Hosts: []string{"127.0.0. 1"}},
		"bracketed v6":             {Hosts: []string{"[::1]"}},
		"userinfo":                 {Hosts: []string{"evil@127.0.0.1"}},
		"CIDR leading zeros":       {CIDRs: []string{"010.020.0.0/16"}},
		"CIDR zone":                {CIDRs: []string{"fe80::%eth0/64"}},
		"uppercase LOCALHOST":      {Hosts: []string{"LOCALHOST"}},
		"localhost trailing dot":   {Hosts: []string{"localhost."}},
		"sub.localhost":            {DNSNames: []string{"*.app.localhost"}},
		"controller by name":       {Hosts: []string{"ctrl.corp.example"}},
		"controller uppercase dot": {Hosts: []string{"CTRL.Corp.Example."}},
		"wildcard over controller": {DNSNames: []string{"*.corp.example"}},
		"DNS name that is an IP":   {DNSNames: []string{"127.0.0.1"}},
		"DNS numeric":              {DNSNames: []string{"foo.2130706433"}},

		// Wildcard DNS that turns a name into any address.
		"nip.io host":          {Hosts: []string{"127.0.0.1.nip.io"}},
		"nip.io dashes":        {Hosts: []string{"127-0-0-1.nip.io"}},
		"sslip.io":             {DNSNames: []string{"169.254.169.254.sslip.io"}},
		"xip.io":               {ForwardAddress: "10.0.0.1.xip.io", Hosts: []string{"fs1.corp.example"}},
		"localtest.me":         {Hosts: []string{"localtest.me"}},
		"lvh.me wildcard":      {DNSNames: []string{"*.lvh.me"}},
		"wildcard over nip.io": {DNSNames: []string{"*.io"}},
	} {
		if got, err := normalizeNetworkTarget(tgt); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}

	// What a corporate network looks like is still accepted, in its
	// canonical spelling.
	for name, c := range map[string]struct {
		in   NetworkTarget
		want func(NetworkTarget) bool
	}{
		"private /16": {NetworkTarget{CIDRs: []string{"10.20.0.0/16"}}, nil},
		"host and domain": {NetworkTarget{Hosts: []string{"10.20.0.5", "FS1.Corp.Example."}, DNSNames: []string{"*.Intranet.Corp.Example."}},
			func(t NetworkTarget) bool {
				return t.Hosts[1] == "fs1.corp.example" && t.DNSNames[0] == "*.intranet.corp.example"
			}},
		"v6 /64":  {NetworkTarget{CIDRs: []string{"2001:DB8:1:2::/64"}}, func(t NetworkTarget) bool { return t.CIDRs[0] == "2001:db8:1:2::/64" }},
		"forward": {NetworkTarget{CIDRs: []string{"10.30.0.0/24"}, ForwardAddress: "10.30.0.10", ForwardPort: 3389}, nil},
		"mapped corporate host is unmapped": {NetworkTarget{Hosts: []string{"::ffff:10.20.0.5"}},
			func(t NetworkTarget) bool { return t.Hosts[0] == "10.20.0.5" }},
		"mapped corporate CIDR is unmapped": {NetworkTarget{CIDRs: []string{"::ffff:10.20.0.0/112"}},
			func(t NetworkTarget) bool { return t.CIDRs[0] == "10.20.0.0/16" }},
	} {
		got, err := normalizeNetworkTarget(c.in)
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if c.want != nil && !c.want(got) {
			t.Errorf("%s: canonical form %+v", name, got)
		}
	}
}

func TestNetworkTargetGuardIsConfigurable(t *testing.T) {
	pinTargetGuard(t)
	t.Setenv("NETWORK_TARGET_MIN_PREFIX", "8")
	t.Setenv("NETWORK_TARGET_DENY_CIDRS", "192.168.50.0/24, 10.200.0.0/16, fc00::/7")
	t.Setenv("NETWORK_TARGET_DENY_DOMAINS", "rebind.example")
	t.Setenv("NETWORK_TARGET_DENY_PORTS", "5432,6379,8000-8010")
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.0.0.0/8"}}); err == nil ||
		!strings.Contains(err.Error(), "10.200.0.0/16") {
		t.Errorf("a /8 overlapping a configured deny network: %v", err)
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"11.0.0.0/8"}, PortRanges: []PortRange{{443, 443}}}); err != nil {
		t.Errorf("NETWORK_TARGET_MIN_PREFIX=8 still refuses a /8: %v", err)
	}
	for name, tgt := range map[string]NetworkTarget{
		"host in configured CIDR": {Hosts: []string{"192.168.50.7"}},
		"mapped host in it":       {Hosts: []string{"::ffff:192.168.50.7"}},
		"ULA when listed":         {Hosts: []string{"fd12::1"}},
		"configured domain":       {DNSNames: []string{"*.x.rebind.example"}},
		"postgres port":           {Hosts: []string{"11.0.0.1"}, PortRanges: []PortRange{{5000, 6000}}},
		"every port":              {Hosts: []string{"11.0.0.1"}},
		"inside port range":       {Hosts: []string{"11.0.0.1"}, PortRanges: []PortRange{{8005, 8005}}},
		"metadata still refused":  {Hosts: []string{"169.254.169.254"}},
	} {
		if _, err := normalizeNetworkTarget(tgt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"11.0.0.1"}, PortRanges: []PortRange{{443, 443}}}); err != nil {
		t.Errorf("a port outside NETWORK_TARGET_DENY_PORTS was refused: %v", err)
	}
	// The configured list replaces the default platform networks.
	if _, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{"10.89.0.0/24"}, PortRanges: []PortRange{{443, 443}}}); err != nil {
		t.Errorf("the default list still applies when NETWORK_TARGET_DENY_CIDRS is set: %v", err)
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

// The reconciler re-validates at emit time: a desired service built by any
// path with a denied target writes nothing to the controller.
func TestEnsureNetworkServiceRefusesADeniedTargetAtEmit(t *testing.T) {
	pinTargetGuard(t)
	f := newFakeNetCtrl()
	zm := newNetTestManager(t, f)
	rec := &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	for _, tgt := range []NetworkTarget{
		{Hosts: []string{"127.0.0.1"}},
		{Hosts: []string{"0177.0.0.1"}},
		{Hosts: []string{"10.20.0.5"}, ForwardAddress: "::ffff:169.254.169.254"},
		{DNSNames: []string{"*.nip.io"}},
	} {
		d := DesiredNetworkService{ApplicationID: "x", OrgID: "o", ServiceName: networkServiceName("x"), Target: tgt}
		if err := rec.ensureNetworkService(context.Background(), zm, d); err == nil {
			t.Errorf("%+v was emitted", tgt)
		}
	}
	if n := f.writeCount(); n != 0 {
		t.Errorf("the controller received %d writes for refused targets", n)
	}
}

// What is checked is what is written: the intercept and host configs carry
// the canonical spellings.
func TestNetworkConfigsCarryTheCanonicalForm(t *testing.T) {
	pinTargetGuard(t)
	tgt, err := normalizeNetworkTarget(NetworkTarget{
		Hosts: []string{"FS1.Corp.Example.", "::ffff:10.20.0.5"}, CIDRs: []string{"10.20.3.4/16"},
		ForwardAddress: "::ffff:10.20.0.9", ForwardPort: 445,
	})
	if err != nil {
		t.Fatal(err)
	}
	addrs := interceptV1Data(tgt)["addresses"].([]string)
	if strings.Join(addrs, ",") != "fs1.corp.example,10.20.0.5,10.20.0.0/16" {
		t.Errorf("intercept addresses = %v", addrs)
	}
	if hostV1Data(tgt)["address"] != "10.20.0.9" {
		t.Errorf("host.v1 address = %v", hostV1Data(tgt)["address"])
	}
}
