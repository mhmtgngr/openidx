package access

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

// A NETWORK TARGET MUST NOT POINT AT THE PLATFORM.
//
// A network resource's service is bound to #ziti-routers: the platform's own
// routers dial whatever the target names. An organization's administrator who
// could name 127.0.0.1, the cloud metadata address, the box's own addresses,
// the container networks Postgres and Redis live on, the controller, or a
// /0 that covers all of them, would have the platform dial its own internals
// on the tenant's behalf. targetGuard refuses those before a target is stored,
// and the reconciler applies it again to what it loads, so a row written
// before the rule (or by hand) is not converged either.
//
// What it refuses, resolve-free (a DNS name is judged by its spelling; the
// router resolves it later, so a name that resolves into a denied network is
// not caught here -- that is what NETWORK_TARGET_DENY_CIDRS on the routers'
// resolver, or egress rules on the router host, are for):
//
//   - loopback, link-local (169.254/16 incl. metadata, fe80::/10),
//     unspecified and multicast addresses, as hosts, forward addresses or
//     anything a CIDR overlaps;
//   - CIDRs broader than NETWORK_TARGET_MIN_PREFIX (default /16 for IPv4;
//     IPv6 gets the same number plus 32, i.e. /48);
//   - anything overlapping NETWORK_TARGET_DENY_CIDRS (comma-separated; the
//     default is the platform's own service networks: the podman and docker
//     bridges and the CGNAT range OpenZiti tunnelers use for intercepts) or
//     an address of one of this host's interfaces;
//   - localhost, *.localhost, this host's name and the controller's host.

// defaultDenyCIDRs are the platform's own networks: container bridges the
// services, Postgres and Redis listen on, and the tunneler's intercept range.
var defaultDenyCIDRs = []string{
	"10.88.0.0/16",  // podman default bridge
	"10.89.0.0/16",  // podman compose networks
	"172.17.0.0/16", // docker default bridge
	"100.64.0.0/10", // CGNAT: ziti-edge-tunnel's intercept/DNS range
}

// alwaysDenied are refused whatever the configuration says.
var alwaysDenied = []string{
	"127.0.0.0/8", "::1/128", // loopback
	"169.254.0.0/16", "fe80::/10", // link-local, incl. 169.254.169.254
	"0.0.0.0/8", "::/128", // unspecified / "this network"
	"224.0.0.0/4", "ff00::/8", // multicast
	"255.255.255.255/32",
	"fd00:ec2::254/128", // AWS IPv6 metadata
}

type networkTargetGuard struct {
	deny          []*net.IPNet
	minPrefixV4   int
	minPrefixV6   int
	platformNames map[string]bool
}

var (
	platformHostsMu sync.Mutex
	platformHosts   []string
)

// SetNetworkTargetPlatformHosts records platform endpoints (the controller
// URL, the routers' addresses) a target may not name. URLs and host:port are
// accepted; the host is what is kept.
func SetNetworkTargetPlatformHosts(hosts ...string) {
	platformHostsMu.Lock()
	defer platformHostsMu.Unlock()
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = u.Hostname()
		} else if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		platformHosts = append(platformHosts, strings.ToLower(strings.Trim(h, "[]")))
	}
}

// targetGuard builds the guard from the environment and the host. It is a
// variable so tests can pin it.
var targetGuard = func() *networkTargetGuard {
	g := &networkTargetGuard{minPrefixV4: 16, platformNames: map[string]bool{"localhost": true}}
	if v := strings.TrimSpace(os.Getenv("NETWORK_TARGET_MIN_PREFIX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 32 {
			g.minPrefixV4 = n
		}
	}
	g.minPrefixV6 = g.minPrefixV4 + 32
	cidrs := append([]string{}, alwaysDenied...)
	if v, ok := os.LookupEnv("NETWORK_TARGET_DENY_CIDRS"); ok {
		cidrs = append(cidrs, strings.Split(v, ",")...)
	} else {
		cidrs = append(cidrs, defaultDenyCIDRs...)
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			g.deny = append(g.deny, n)
		}
	}
	// This host's own addresses.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				bits := 32
				if ipn.IP.To4() == nil {
					bits = 128
				}
				g.deny = append(g.deny, &net.IPNet{IP: ipn.IP, Mask: net.CIDRMask(bits, bits)})
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		g.platformNames[strings.ToLower(h)] = true
	}
	platformHostsMu.Lock()
	for _, h := range platformHosts {
		if ip := net.ParseIP(h); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			g.deny = append(g.deny, &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)})
		} else {
			g.platformNames[h] = true
		}
	}
	platformHostsMu.Unlock()
	return g
}

func overlaps(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// checkIP refuses an address the platform owns or that is never a target.
func (g *networkTargetGuard) checkIP(what string, ip net.IP) error {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%s %s is a loopback, link-local, unspecified or multicast address", what, ip)
	}
	for _, d := range g.deny {
		if d.Contains(ip) {
			return fmt.Errorf("%s %s is inside %s, a network the platform itself uses", what, ip, d)
		}
	}
	return nil
}

// checkCIDR refuses a network broader than the limit or overlapping a denied one.
func (g *networkTargetGuard) checkCIDR(n *net.IPNet) error {
	ones, bits := n.Mask.Size()
	limit := g.minPrefixV4
	if bits == 128 {
		limit = g.minPrefixV6
	}
	if ones < limit {
		return fmt.Errorf("CIDR %s is broader than /%d; split it into the networks the resource covers", n, limit)
	}
	for _, d := range g.deny {
		if overlaps(n, d) {
			return fmt.Errorf("CIDR %s overlaps %s, a network the platform itself uses", n, d)
		}
	}
	return nil
}

// checkName refuses a host name that names the platform (resolve-free).
func (g *networkTargetGuard) checkName(what, name string) error {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "*."), "."))
	if n == "localhost" || strings.HasSuffix(n, ".localhost") || g.platformNames[n] {
		return fmt.Errorf("%s %q names the platform itself", what, name)
	}
	for p := range g.platformNames {
		// *.example.com covers the controller at ctrl.example.com.
		if strings.HasPrefix(name, "*.") && strings.HasSuffix(p, "."+n) {
			return fmt.Errorf("%s %q covers %s, a platform host", what, name, p)
		}
	}
	return nil
}

// checkHost judges a host or forward address: an IP by its address, a name by
// its spelling.
func (g *networkTargetGuard) checkHost(what, h string) error {
	if ip := net.ParseIP(h); ip != nil {
		return g.checkIP(what, ip)
	}
	return g.checkName(what, h)
}

// check applies the guard to a target already syntactically normalized.
func (g *networkTargetGuard) check(t NetworkTarget) []string {
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, h := range t.Hosts {
		add(g.checkHost("host", h))
	}
	for _, c := range t.CIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			add(g.checkCIDR(n))
		}
	}
	for _, d := range t.DNSNames {
		add(g.checkName("DNS name", d))
	}
	if t.ForwardAddress != "" {
		add(g.checkHost("forward address", t.ForwardAddress))
	}
	return errs
}
