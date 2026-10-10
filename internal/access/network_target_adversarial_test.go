package access

import (
	"context"
	"testing"
)

// An adversarial pass: every way found to make a target reach Postgres on
// the platform (127.0.0.1:5432), the metadata service or the controller,
// through every field the target has. Each must be refused by
// normalizeNetworkTarget (the API's gate), and none may produce configs the
// emit-time gate accepts.
func TestNetworkTargetAdversarialPass(t *testing.T) {
	pinTargetGuard(t)
	withPlatformHosts(t, "https://ctrl.corp.example:1280", "10.0.0.99")
	pg := []PortRange{{5432, 5432}}

	loopbackSpellings := []string{
		"127.0.0.1", "127.0.0.1.", "127.1", "127.0.1", "127.000.000.001", "0177.0.0.1", "0x7f.0.0.1",
		"0x7f.1", "0x7f000001", "2130706433", "017700000001", "127.0.0.1%00", "127.0.0.1%25",
		"127.0.0.1 ", " 127.0.0.1\t", "127.0.0.1\n", "[127.0.0.1]", "127.0.0.1:5432", "user@127.0.0.1",
		"127.0.0.1#x", "127.0.0.1/32",
		"::1", "0:0:0:0:0:0:0:1", "::0:1", "[::1]", "::1%lo", "::ffff:127.0.0.1", "::FFFF:7F00:1",
		"0:0:0:0:0:ffff:7f00:1", "::ffff:0177.0.0.1", "::127.0.0.1", "::7f00:1",
		"64:ff9b::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::7f00:1", "2002:7f00:1::",
		"2001:0:4136:e378:8000:63bf:80ff:fffe", // Teredo, client 127.0.0.1 obfuscated
		"0.0.0.0", "0", "0.0.0.1",
		"localhost", "LOCALHOST", "localhost.", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
		"a.localhost", "127.0.0.1.nip.io", "127-0-0-1.nip.io", "7f000001.nip.io", "127.0.0.1.sslip.io",
		"localtest.me", "x.lvh.me", "127.0.0.1.xip.io",
		"host.containers.internal", "host.docker.internal", "postgres", "oidx-pg", "redis",
		"%31%32%37.0.0.1", "127。0。0。1", "１２７.０.０.１",
	}
	metadataSpellings := []string{
		"169.254.169.254", "0xa9fea9fe", "2852039166", "0251.0376.0251.0376", "169.254.43518",
		"::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::",
		"fd00:ec2::254", "metadata.google.internal", "169.254.169.254.nip.io", "instance-data.ec2.internal",
	}
	controllerSpellings := []string{
		"ctrl.corp.example", "CTRL.CORP.EXAMPLE.", "10.0.0.99", "::ffff:10.0.0.99", "64:ff9b::a00:63",
	}

	type field struct {
		name string
		mk   func(v string) NetworkTarget
	}
	fields := []field{
		{"hosts", func(v string) NetworkTarget { return NetworkTarget{Hosts: []string{v}, PortRanges: pg} }},
		{"forward_address", func(v string) NetworkTarget {
			return NetworkTarget{Hosts: []string{"fs1.corp.example"}, ForwardAddress: v, ForwardPort: 5432}
		}},
		{"dns_names", func(v string) NetworkTarget { return NetworkTarget{DNSNames: []string{v}, PortRanges: pg} }},
		{"dns_names wildcard", func(v string) NetworkTarget { return NetworkTarget{DNSNames: []string{"*." + v}, PortRanges: pg} }},
		{"cidrs /32", func(v string) NetworkTarget { return NetworkTarget{CIDRs: []string{v + "/32"}, PortRanges: pg} }},
		{"cidrs /128", func(v string) NetworkTarget { return NetworkTarget{CIDRs: []string{v + "/128"}, PortRanges: pg} }},
	}
	all := append(append(append([]string{}, loopbackSpellings...), metadataSpellings...), controllerSpellings...)
	for _, f := range fields {
		for _, v := range all {
			tgt := f.mk(v)
			got, err := normalizeNetworkTarget(tgt)
			if err == nil {
				t.Errorf("%s %q: accepted as %+v", f.name, v, got)
				continue
			}
			// And the raw value never passes the emit-time gate either.
			if errs := guardEmittedConfigs(interceptV1Data(tgt), hostV1Data(tgt)); len(errs) == 0 {
				t.Errorf("%s %q: the emit-time gate accepted the raw value", f.name, v)
			}
		}
	}

	// Covering CIDRs: anything that contains loopback, metadata or the
	// controller, in v4 and in every v6 form that embeds v4.
	for _, c := range []string{
		"127.0.0.0/8", "126.0.0.0/7", "0.0.0.0/1", "169.254.0.0/16", "10.0.0.0/16", "10.0.0.0/24",
		"::/0", "::/96", "::ffff:0:0/96", "::ffff:7f00:0/104", "64:ff9b::/96", "64:ff9b::7f00:0/120",
		"2002::/16", "2002:7f00::/24", "2001::/32", "2001:0:4136:e378::/64",
	} {
		if got, err := normalizeNetworkTarget(NetworkTarget{CIDRs: []string{c}, PortRanges: pg}); err == nil {
			t.Errorf("CIDR %q: accepted as %+v", c, got)
		}
	}
}

// The registries: one address from every IANA special-purpose block that is
// not plain private or global unicast is refused.
func TestNetworkTargetRefusesTheSpecialPurposeRegistries(t *testing.T) {
	pinTargetGuard(t)
	for _, a := range []string{
		"0.1.2.3", "100.64.0.1", "100.127.255.254", "127.255.255.254", "169.254.0.1", "192.0.0.9",
		"192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::2", "100::1", "2001::1", "2001:2::1", "2001:10::1", "2001:20::1",
		"2001:db8::1", "2002::1", "3fff::1", "5f00::1", "fe80::1", "fec0::1", "ff02::1",
		"64:ff9b::808:808", "64:ff9b:1::1",
	} {
		if got, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{a}}); err == nil {
			t.Errorf("%s: accepted as %+v", a, got)
		}
	}
	// Ordinary private and global unicast still pass.
	for _, a := range []string{"10.0.0.5", "172.16.0.4", "192.168.1.10", "8.8.8.8", "2a02:1234::1", "fd12:3456::1"} {
		if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{a}}); err != nil {
			t.Errorf("%s: refused: %v", a, err)
		}
	}
}

// The gate reads the emitted maps, not the target: a host.v1 or intercept.v1
// map that disagrees with what a target would produce is judged as it is.
func TestGuardEmittedConfigsJudgesTheMapsThemselves(t *testing.T) {
	pinTargetGuard(t)
	goodIntercept := map[string]interface{}{
		"protocols": []string{"tcp"}, "addresses": []string{"10.0.0.5"},
		"portRanges": []map[string]interface{}{{"low": 445, "high": 445}},
	}
	goodHost := map[string]interface{}{"protocol": "tcp", "address": "10.0.0.5", "port": 445}
	if errs := guardEmittedConfigs(goodIntercept, goodHost); len(errs) != 0 {
		t.Fatalf("a clean pair was refused: %v", errs)
	}
	for name, h := range map[string]map[string]interface{}{
		"host.v1 address differs from intercept": {"protocol": "tcp", "address": "127.0.0.1", "port": 5432},
		"non-canonical address":                  {"protocol": "tcp", "address": "::ffff:10.0.0.5", "port": 445},
		"uppercase name":                         {"protocol": "tcp", "address": "FS1.corp.example", "port": 445},
		"forwardAddress unbounded":               {"protocol": "tcp", "forwardAddress": true, "port": 445},
		"allowedAddresses without forward":       {"protocol": "tcp", "address": "10.0.0.5", "allowedAddresses": []string{"127.0.0.1"}, "port": 445},
		"allowedAddresses with loopback": {"protocol": "tcp", "forwardAddress": true,
			"allowedAddresses": []string{"10.0.0.5", "127.0.0.0/8"}, "port": 445},
		"allowedAddresses wildcard": {"protocol": "tcp", "forwardAddress": true,
			"allowedAddresses": []string{"*.nip.io"}, "port": 445},
		"empty allowedAddresses": {"protocol": "tcp", "forwardAddress": true, "allowedAddresses": []string{}, "port": 445},
		"forwardPort unbounded":  {"protocol": "tcp", "address": "10.0.0.5", "forwardPort": true},
		"port 0":                 {"protocol": "tcp", "address": "10.0.0.5", "port": 0},
		"bad allowed port range": {"protocol": "tcp", "address": "10.0.0.5", "forwardPort": true,
			"allowedPortRanges": []map[string]interface{}{{"low": 0, "high": 70000}}},
		"protocol icmp":           {"protocol": "icmp", "address": "10.0.0.5", "port": 445},
		"forwardProtocol unbound": {"forwardProtocol": true, "address": "10.0.0.5", "port": 445},
		"no address at all":       {"protocol": "tcp", "port": 445},
		"address of another type": {"protocol": "tcp", "address": []interface{}{"127.0.0.1"}, "port": 445},
	} {
		if errs := guardEmittedConfigs(goodIntercept, h); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, i := range map[string]map[string]interface{}{
		"intercept loopback": {"protocols": []string{"tcp"}, "addresses": []string{"10.0.0.5", "127.0.0.1"},
			"portRanges": []map[string]interface{}{{"low": 445, "high": 445}}},
		"intercept non-canonical CIDR": {"protocols": []string{"tcp"}, "addresses": []string{"10.0.0.77/16"},
			"portRanges": []map[string]interface{}{{"low": 445, "high": 445}}},
		"intercept no addresses": {"protocols": []string{"tcp"}, "addresses": []string{},
			"portRanges": []map[string]interface{}{{"low": 445, "high": 445}}},
		"intercept bad range": {"protocols": []string{"tcp"}, "addresses": []string{"10.0.0.5"},
			"portRanges": []map[string]interface{}{{"low": 9, "high": 1}}},
	} {
		if errs := guardEmittedConfigs(i, goodHost); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Router endpoints read from the controller join the denylist.
func TestRefreshRouterHostsDeniesTheRouters(t *testing.T) {
	pinTargetGuard(t)
	routerHostsMu.Lock()
	saved := routerHosts
	routerHostsMu.Unlock()
	t.Cleanup(func() {
		routerHostsMu.Lock()
		routerHosts = saved
		routerHostsMu.Unlock()
	})
	stub := newZitiStub(t)
	stub.ok("GET /edge/management/v1/edge-routers",
		`{"data":[{"hostname":"edge1.corp.example","supportedProtocols":{"tls":"tls://172.16.0.77:3022","ws":"wss://[2a02:1234::77]:3023"}}]}`)
	zm := zitiManagerAgainst(t, stub, nil)
	if err := refreshRouterHosts(context.Background(), zm); err != nil {
		t.Fatalf("refreshRouterHosts: %v", err)
	}
	// pinTargetGuard drops host addresses; read the real guard's lists.
	for _, h := range []string{"edge1.corp.example", "172.16.0.77", "2a02:1234::77"} {
		found := false
		routerHostsMu.Lock()
		for _, r := range routerHosts {
			found = found || r == h
		}
		routerHostsMu.Unlock()
		if !found {
			t.Errorf("router host %s was not recorded", h)
		}
	}
	if _, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"edge1.corp.example"}}); err == nil {
		t.Error("a target naming the router was accepted")
	}
}
