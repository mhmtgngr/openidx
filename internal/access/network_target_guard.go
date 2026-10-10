package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A NETWORK TARGET MUST NOT POINT AT THE PLATFORM.
//
// A network resource's service is bound to #ziti-routers: the platform's own
// routers dial whatever the target names. An organization's administrator who
// could name 127.0.0.1, the cloud metadata address, the box's own addresses,
// the container networks Postgres and Redis live on, the controller, or a
// /0 that covers all of them, would have the platform dial its own internals
// on the tenant's behalf.
//
// TWO HALVES. First every address is CANONICALISED (canonicalHost,
// canonicalPrefix, canonicalDNSName): one strict parse, IPv4-mapped IPv6
// unmapped, no zone ids, no percent-encoding, no numeric spellings other than
// a dotted quad (127.1, 2130706433, 0x7f.1 and 0177.0.0.1 are refused, not
// reinterpreted), names lower-cased with one trailing dot removed. The
// canonical form is what is checked, what is stored, and what the reconciler
// writes into intercept.v1/host.v1, so the guard and the router's parser read
// the same string. Then targetGuard refuses what points at the platform.
//
// What it refuses:
//
//   - loopback, link-local (169.254/16 incl. metadata, fe80::/10),
//     unspecified, multicast, broadcast, 0/8, 192.0.0.0/24, 198.18/15,
//     240/4, ::/128, ::1, the AWS IPv6 metadata address; an IPv6 address
//     that embeds an IPv4 one (NAT64 64:ff9b::/96 and 64:ff9b:1::/48, 6to4
//     2002::/16) is judged by the IPv4 address it carries, and a CIDR
//     overlapping those translation ranges is refused outright;
//   - CIDRs broader than NETWORK_TARGET_MIN_PREFIX (default /16 for IPv4;
//     IPv6 gets the same number plus 32, i.e. /48);
//   - anything overlapping NETWORK_TARGET_DENY_CIDRS (comma-separated; the
//     default is the platform's own service networks: the podman and docker
//     bridges and the CGNAT range OpenZiti tunnelers use for intercepts;
//     fc00::/7 only when listed) or an address of this host's interfaces;
//   - localhost, *.localhost, this host's name, the controller's host, the
//     wildcard-DNS services that turn a name into any IP (nip.io, sslip.io,
//     xip.io, localtest.me, lvh.me, plus NETWORK_TARGET_DENY_DOMAINS), and a
//     wildcard that covers any of those or is a bare top-level domain;
//   - port ranges overlapping NETWORK_TARGET_DENY_PORTS (empty by default).
//
// DNS names are judged by spelling only: the router resolves them later, so a
// name of the tenant's own that resolves into a denied network is not caught
// here. Egress rules on the router hosts are the backstop for that.

// defaultDenyCIDRs are the platform's own networks: container bridges the
// services, Postgres and Redis listen on, and the tunneler's intercept range.
var defaultDenyCIDRs = []string{
	"10.88.0.0/16",  // podman default bridge
	"10.89.0.0/16",  // podman compose networks
	"172.17.0.0/16", // docker default bridge
}

// alwaysDenied are refused whatever the configuration says: every entry of
// the IANA IPv4 and IPv6 special-purpose address registries that is not a
// plain private or globally routable unicast block, plus the overlay's own
// CGNAT range and the cloud metadata addresses. (10/8, 172.16/12,
// 192.168/16 and fc00::/7 are where corporate networks live, so they are
// refused only where the platform uses them: the defaults above, the
// interfaces found at startup, NETWORK_TARGET_DENY_CIDRS.)
var alwaysDenied = []string{
	// IPv4 (RFC 6890 registry)
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // CGNAT; ziti-edge-tunnel's intercept/DNS range
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, incl. 169.254.169.254
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // 6to4 relay anycast
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, incl. 255.255.255.255
	// IPv6
	"::/96",             // IPv4-compatible (deprecated), incl. :: and ::1
	"::1/128",           // loopback
	"64:ff9b::/96",      // NAT64 well-known
	"64:ff9b:1::/48",    // NAT64 local-use
	"100::/64",          // discard-only
	"2001::/32",         // Teredo (embedded IPv4, obfuscated)
	"2001:2::/48",       // benchmarking
	"2001:10::/28",      // ORCHID
	"2001:20::/28",      // ORCHIDv2
	"2001:db8::/32",     // documentation
	"2002::/16",         // 6to4
	"3fff::/20",         // documentation
	"5f00::/16",         // SRv6 SIDs
	"fe80::/10",         // link-local
	"fec0::/10",         // site-local (deprecated)
	"ff00::/8",          // multicast
	"fd00:ec2::254/128", // AWS IPv6 metadata
}

// bridgeInterface matches the host interfaces whose networks are the
// platform's container and overlay networks.
var bridgeInterface = regexp.MustCompile(`^(podman|cni-|cni0|docker|br-|virbr|veth|ziti|tun|tap|flannel|cali|weave|kube)`)

// hostInterfaces lists this host's interfaces; a variable so tests can make
// the guard independent of the machine they run on.
var hostInterfaces = net.Interfaces

// translationPrefixes embed an IPv4 address in an IPv6 one.
var (
	nat64WKP   = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	mappedV4   = netip.MustParsePrefix("::ffff:0:0/96")
)

// defaultDenyDomains turn any name into any address (127.0.0.1.nip.io).
// The container runtimes' and clouds' own names for the host and its
// metadata service are refused with them.
var defaultDenyDomains = []string{
	"nip.io", "sslip.io", "xip.io", "localtest.me", "lvh.me", "traefik.me", "localhost.direct",
	"localhost", "localdomain",
	"host.containers.internal", "host.docker.internal", "gateway.docker.internal",
	"docker.internal", "containers.internal",
	"metadata.google.internal", "ec2.internal", "compute.internal",
}

// Router endpoints discovered from the controller (refreshRouterHosts).
var (
	routerHostsMu sync.Mutex
	routerHosts   []string
)

type networkTargetGuard struct {
	deny          []netip.Prefix
	minPrefixV4   int
	minPrefixV6   int
	platformNames map[string]bool
	denyDomains   []string
	denyPorts     []PortRange
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
		platformHosts = append(platformHosts, strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), "."))
	}
}

func hostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

func envList(name string) ([]string, bool) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return nil, false
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, true
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
	if extra, ok := envList("NETWORK_TARGET_DENY_CIDRS"); ok {
		cidrs = append(cidrs, extra...)
	} else {
		cidrs = append(cidrs, defaultDenyCIDRs...)
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			g.deny = append(g.deny, unmapPrefix(p).Masked())
		}
	}
	g.denyDomains = append([]string{}, defaultDenyDomains...)
	if extra, ok := envList("NETWORK_TARGET_DENY_DOMAINS"); ok {
		for _, d := range extra {
			g.denyDomains = append(g.denyDomains, strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(d), "*."), "."))
		}
	}
	if ports, ok := envList("NETWORK_TARGET_DENY_PORTS"); ok {
		for _, p := range ports {
			if pr, err := parsePortList(p); err == nil {
				g.denyPorts = append(g.denyPorts, pr...)
			}
		}
	}
	// This host's own addresses, and the whole network of every container,
	// bridge or overlay interface actually present (podman/CNI/docker
	// networks whose ranges differ from the defaults above).
	if ifaces, err := hostInterfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ad, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				ad = ad.Unmap()
				g.deny = append(g.deny, hostPrefix(ad))
				if bridgeInterface.MatchString(ifc.Name) {
					ones, _ := ipn.Mask.Size()
					if ad.Is4() && ipn.IP.To4() != nil && len(ipn.Mask) == 16 {
						ones -= 96
					}
					if p, err := ad.Prefix(ones); err == nil {
						g.deny = append(g.deny, p)
					}
				}
			}
		}
	}
	routerHostsMu.Lock()
	for _, h := range routerHosts {
		if a, err := netip.ParseAddr(h); err == nil {
			g.deny = append(g.deny, hostPrefix(a.Unmap()))
		} else {
			g.platformNames[h] = true
		}
	}
	routerHostsMu.Unlock()
	if h, err := os.Hostname(); err == nil && h != "" {
		g.platformNames[strings.ToLower(h)] = true
	}
	platformHostsMu.Lock()
	for _, h := range platformHosts {
		if a, err := netip.ParseAddr(h); err == nil {
			g.deny = append(g.deny, hostPrefix(a.Unmap()))
		} else {
			g.platformNames[h] = true
		}
	}
	platformHostsMu.Unlock()
	return g
}

// ---- canonicalisation ----

// numericLabel matches a label an IP parser somewhere might read as a number:
// decimal, octal-looking, or 0x-hex.
var numericLabel = regexp.MustCompile(`^(0[xX][0-9a-fA-F]*|[0-9]+)$`)

// looksNumeric reports whether a name's last label is numeric. No top-level
// domain is, so such a "name" is an address in another spelling (127.1,
// 2130706433, 0x7f.1, 0177.0.0.1) that some parser would accept.
func looksNumeric(name string) bool {
	labels := strings.Split(name, ".")
	return numericLabel.MatchString(labels[len(labels)-1])
}

// unmapPrefix turns ::ffff:a.b.c.d/n (n >= 96) into a.b.c.d/(n-96).
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// canonicalAddr parses a strict IP literal: no zone, IPv4-mapped unmapped.
func canonicalAddr(s string) (netip.Addr, bool, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false, nil
	}
	if a.Zone() != "" {
		return netip.Addr{}, true, fmt.Errorf("%q carries a zone id", s)
	}
	return a.Unmap(), true, nil
}

// canonicalHost returns the one spelling of a host or forward address that is
// checked, stored and written to Ziti: an IP literal in netip's form, or a
// lower-case host name without its trailing dot.
func canonicalHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "%/\\@ \t\r\n[]") {
		return "", fmt.Errorf("%q is neither an IP address nor a host name", s)
	}
	trimmed := strings.TrimSuffix(s, ".")
	if a, isIP, err := canonicalAddr(trimmed); err != nil {
		return "", err
	} else if isIP {
		return a.String(), nil
	}
	name := strings.ToLower(trimmed)
	if strings.Contains(name, ":") || !validHostName(name) {
		return "", fmt.Errorf("%q is neither an IP address nor a host name", s)
	}
	// A single-label name resolves through /etc/hosts, search domains or the
	// container runtime's DNS on the router's host (postgres, redis,
	// oidx-pg): a fully qualified name only.
	if !strings.Contains(name, ".") {
		return "", fmt.Errorf("%q is not a fully qualified name", s)
	}
	if looksNumeric(name) {
		return "", fmt.Errorf("%q is an address in a spelling other than a dotted quad; write it as one", s)
	}
	return name, nil
}

// canonicalPrefix parses a strict CIDR and returns its masked canonical form.
func canonicalPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q does not parse", s)
	}
	return unmapPrefix(p).Masked(), nil
}

// canonicalDNSName returns a domain (with an optional leading *.) lower-cased
// without its trailing dot. A wildcard must sit under at least two labels.
func canonicalDNSName(s string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	wild := strings.HasPrefix(name, "*.")
	base := strings.TrimPrefix(name, "*.")
	if strings.ContainsAny(base, "*%/\\@ \t:[]") || !validHostName(base) || !strings.Contains(base, ".") {
		return "", fmt.Errorf("%q is not a domain (a leading *. is allowed)", s)
	}
	if looksNumeric(base) {
		return "", fmt.Errorf("%q is an address, not a domain; put it under hosts or CIDRs", s)
	}
	if _, isIP, _ := canonicalAddr(base); isIP {
		return "", fmt.Errorf("%q is an address, not a domain", s)
	}
	if wild && strings.Count(base, ".") < 1 {
		return "", fmt.Errorf("%q covers a whole top-level domain", s)
	}
	return name, nil
}

// ---- the checks ----

// embeddedV4 returns the IPv4 address an IPv6 translation address carries.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64WKP.Contains(a), nat64Local.Contains(a), mappedV4.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// checkAddr refuses an address the platform owns or that is never a target.
func (g *networkTargetGuard) checkAddr(what string, a netip.Addr) error {
	if v4, ok := embeddedV4(a); ok {
		if err := g.checkAddr(what, v4); err != nil {
			return fmt.Errorf("%s %s embeds %s: %w", what, a, v4, err)
		}
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return fmt.Errorf("%s %s is a loopback, link-local, unspecified or multicast address", what, a)
	}
	for _, d := range g.deny {
		if d.Contains(a) {
			return fmt.Errorf("%s %s is inside %s, a network the platform itself uses", what, a, d)
		}
	}
	return nil
}

// checkPrefix refuses a network broader than the limit, overlapping a denied
// one, or overlapping an IPv4-in-IPv6 translation range.
func (g *networkTargetGuard) checkPrefix(p netip.Prefix) error {
	limit := g.minPrefixV4
	if p.Addr().Is6() {
		limit = g.minPrefixV6
		for _, tr := range []netip.Prefix{nat64WKP, nat64Local, sixToFour, mappedV4} {
			if p.Overlaps(tr) {
				return fmt.Errorf("CIDR %s overlaps %s, which embeds IPv4 addresses; use the IPv4 network", p, tr)
			}
		}
	}
	if p.Bits() < limit {
		return fmt.Errorf("CIDR %s is broader than /%d; split it into the networks the resource covers", p, limit)
	}
	for _, d := range g.deny {
		if p.Overlaps(d) {
			return fmt.Errorf("CIDR %s overlaps %s, a network the platform itself uses", p, d)
		}
	}
	return nil
}

// checkName refuses a canonical name that names the platform (resolve-free).
func (g *networkTargetGuard) checkName(what, name string) error {
	wild := strings.HasPrefix(name, "*.")
	base := strings.TrimPrefix(name, "*.")
	if g.platformNames[base] {
		return fmt.Errorf("%s %q names the platform itself", what, name)
	}
	for _, d := range g.denyDomains {
		if base == d || strings.HasSuffix(base, "."+d) {
			return fmt.Errorf("%s %q is under %s, which resolves names to arbitrary addresses or to this host", what, name, d)
		}
		if wild && strings.HasSuffix(d, "."+base) {
			return fmt.Errorf("%s %q covers %s", what, name, d)
		}
	}
	for p := range g.platformNames {
		if wild && strings.HasSuffix(p, "."+base) {
			return fmt.Errorf("%s %q covers %s, a platform host", what, name, p)
		}
	}
	return nil
}

// checkHost judges a canonical host or forward address.
func (g *networkTargetGuard) checkHost(what, h string) error {
	if a, err := netip.ParseAddr(h); err == nil {
		return g.checkAddr(what, a)
	}
	return g.checkName(what, h)
}

// ---- the gate over what is emitted ----

// guardEmittedConfigs is the one gate between a network target and the
// controller. It reads the intercept.v1 and host.v1 data exactly as they will
// be written -- not the target they were built from -- and judges every
// address, port and protocol that appears in either: intercept addresses,
// host.v1 address/allowedAddresses, port/portRanges/allowedPortRanges,
// protocol/allowedProtocols. A value that is not already in its canonical
// spelling is refused too, so nothing reaches Ziti in a form the guard did not
// parse itself. Both the API (normalizeNetworkTarget) and the reconciler
// (ensureNetworkService) call it, on the same maps they hand to EnsureConfig.
func guardEmittedConfigs(intercept, host map[string]interface{}) []string {
	g := targetGuard()
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	addresses := func(where string, v interface{}) {
		switch x := v.(type) {
		case nil:
		case string:
			add(g.checkEmittedAddress(where, x))
		case []string:
			if len(x) == 0 {
				add(fmt.Errorf("%s is empty", where))
			}
			for _, s := range x {
				add(g.checkEmittedAddress(where, s))
			}
		default:
			add(fmt.Errorf("%s has an unexpected shape %T", where, v))
		}
	}
	ports := func(where string, v interface{}) {
		switch x := v.(type) {
		case nil:
		case int:
			add(g.checkEmittedPorts(where, x, x))
		case []map[string]interface{}:
			if len(x) == 0 {
				add(fmt.Errorf("%s is empty", where))
			}
			for _, r := range x {
				lo, ok1 := r["low"].(int)
				hi, ok2 := r["high"].(int)
				if !ok1 || !ok2 {
					add(fmt.Errorf("%s holds a malformed range", where))
					continue
				}
				add(g.checkEmittedPorts(where, lo, hi))
			}
		default:
			add(fmt.Errorf("%s has an unexpected shape %T", where, v))
		}
	}
	protocols := func(where string, v interface{}) {
		var list []string
		switch x := v.(type) {
		case nil:
			return
		case string:
			list = []string{x}
		case []string:
			list = x
		default:
			add(fmt.Errorf("%s has an unexpected shape %T", where, v))
			return
		}
		for _, p := range list {
			if p != "tcp" && p != "udp" {
				add(fmt.Errorf("%s %q is not tcp or udp", where, p))
			}
		}
	}

	addresses("intercept.v1 addresses", intercept["addresses"])
	ports("intercept.v1 portRanges", intercept["portRanges"])
	protocols("intercept.v1 protocols", intercept["protocols"])

	addresses("host.v1 address", host["address"])
	addresses("host.v1 allowedAddresses", host["allowedAddresses"])
	ports("host.v1 port", host["port"])
	ports("host.v1 allowedPortRanges", host["allowedPortRanges"])
	protocols("host.v1 protocol", host["protocol"])
	protocols("host.v1 allowedProtocols", host["allowedProtocols"])
	// A forward* switch with nothing to bound it would let the dialer choose.
	for _, pair := range [][2]string{{"forwardAddress", "allowedAddresses"}, {"forwardPort", "allowedPortRanges"}, {"forwardProtocol", "allowedProtocols"}} {
		if host[pair[0]] == true && host[pair[1]] == nil {
			add(fmt.Errorf("host.v1 %s is set without %s", pair[0], pair[1]))
		}
		if host[pair[0]] != true && host[pair[1]] != nil {
			add(fmt.Errorf("host.v1 %s is set without %s", pair[1], pair[0]))
		}
	}
	if host["address"] == nil && host["forwardAddress"] != true {
		add(fmt.Errorf("host.v1 has neither address nor forwardAddress"))
	}
	if host["port"] == nil && host["forwardPort"] != true {
		add(fmt.Errorf("host.v1 has neither port nor forwardPort"))
	}
	return errs
}

// checkEmittedAddress judges one address string as Ziti will read it: a CIDR,
// an IP literal, a *.domain wildcard or a host name, each of which must
// already be in its canonical spelling.
func (g *networkTargetGuard) checkEmittedAddress(where, s string) error {
	if strings.Contains(s, "/") {
		p, err := canonicalPrefix(s)
		if err != nil {
			return fmt.Errorf("%s: CIDR %w", where, err)
		}
		if p.String() != s {
			return fmt.Errorf("%s: %q is not in canonical form (%s)", where, s, p)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%s: %s covers every address", where, s)
		}
		return g.checkPrefix(p)
	}
	if strings.HasPrefix(s, "*.") {
		c, err := canonicalDNSName(s)
		if err != nil {
			return fmt.Errorf("%s: DNS name %w", where, err)
		}
		if c != s {
			return fmt.Errorf("%s: %q is not in canonical form (%s)", where, s, c)
		}
		return g.checkName(where, s)
	}
	c, err := canonicalHost(s)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if c != s {
		return fmt.Errorf("%s: %q is not in canonical form (%s)", where, s, c)
	}
	return g.checkHost(where, s)
}

// checkEmittedPorts refuses a range outside 1-65535 or overlapping
// NETWORK_TARGET_DENY_PORTS.
func (g *networkTargetGuard) checkEmittedPorts(where string, lo, hi int) error {
	if lo < 1 || hi > 65535 || lo > hi {
		return fmt.Errorf("%s %d-%d is not within 1-65535 with low <= high", where, lo, hi)
	}
	for _, d := range g.denyPorts {
		if lo <= d.High && d.Low <= hi {
			return fmt.Errorf("%s %d-%d covers %d-%d, which NETWORK_TARGET_DENY_PORTS refuses", where, lo, hi, d.Low, d.High)
		}
	}
	return nil
}

// ---- router endpoints ----

// refreshRouterHosts records every edge router's advertised host (its
// hostname and the hosts of its supportedProtocols listener URLs), and the
// addresses those names resolve to, so a target cannot name a router. Names
// are the platform's own, so resolving them here is safe; a lookup that
// fails keeps the name only.
func refreshRouterHosts(ctx context.Context, zm *ZitiManager) error {
	data, status, err := zm.mgmtRequest("GET", "/edge/management/v1/edge-routers?limit=1000", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("unexpected status %d listing edge routers", status)
	}
	var resp struct {
		Data []struct {
			Hostname           string            `json:"hostname"`
			SupportedProtocols map[string]string `json:"supportedProtocols"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	seen := map[string]bool{}
	var hosts []string
	addHost := func(h string) {
		h = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
		if _, err := netip.ParseAddr(h); err == nil {
			return
		}
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if ips, err := net.DefaultResolver.LookupNetIP(lctx, "ip", h); err == nil {
			for _, ip := range ips {
				s := ip.Unmap().String()
				if !seen[s] {
					seen[s] = true
					hosts = append(hosts, s)
				}
			}
		}
	}
	for _, r := range resp.Data {
		addHost(r.Hostname)
		for _, u := range r.SupportedProtocols {
			if pu, err := url.Parse(u); err == nil && pu.Host != "" {
				addHost(pu.Hostname())
			}
		}
	}
	routerHostsMu.Lock()
	routerHosts = hosts
	routerHostsMu.Unlock()
	return nil
}
