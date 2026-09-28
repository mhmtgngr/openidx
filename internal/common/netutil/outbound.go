package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The platform makes HTTP requests to URLs that an organization's
// administrator types in: webhook subscriptions, audit-stream webhooks,
// outbound SCIM targets, SSF stream receivers, SAML metadata. Those requests
// start inside the platform's network, so a URL naming an internal address
// turns an organization administrator into a client of every service the
// platform can reach -- the database's HTTP admin ports, the other services'
// APIs, the cloud metadata endpoint at 169.254.169.254 -- and wherever the
// platform stores or shows the answer, a reader of it.
//
// OutboundGuard is the one decision about where such a request may go. It is
// made twice: when the URL is saved (CheckURL, so the administrator is told at
// once) and at every connection (DialContext, so a name that resolved to a
// public address when it was saved and to an internal one now -- DNS
// rebinding -- is still refused). The connection is made to the exact address
// that was checked; nothing resolves the name a second time. Redirects are not
// followed, since the target of a redirect is chosen by whoever answers.

// OutboundAllowlistEnv names the operator's escape hatch: comma-separated
// CIDRs, IP addresses and host names ("hooks.corp.example", "*.corp.example")
// that organization-configured requests may reach although they are internal.
// Empty, the default, allows none.
const OutboundAllowlistEnv = "OIDX_OUTBOUND_ALLOWLIST"

// ErrDestinationNotAllowed is wrapped by every refusal the guard makes.
var ErrDestinationNotAllowed = errors.New("destination not allowed")

// DestinationError is a refused destination. It names the host the caller
// supplied and what kind of address it is, never the address a name resolved
// to: that would tell an organization administrator how the platform's
// internal names resolve.
type DestinationError struct {
	Host   string
	Reason string
}

func (e *DestinationError) Error() string { return e.Host + " " + e.Reason }

// Unwrap lets errors.Is(err, ErrDestinationNotAllowed) find the refusal.
func (e *DestinationError) Unwrap() error { return ErrDestinationNotAllowed }

// Resolver looks a host name up. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// LookupNetIP calls f.
func (f ResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

// Allowlist is the parsed OIDX_OUTBOUND_ALLOWLIST.
type Allowlist struct {
	prefixes []netip.Prefix
	hosts    []string // lower-case; a leading "*." matches any subdomain
}

// ParseAllowlist parses a comma-separated list of CIDRs, IP addresses and
// host names. An entry that is none of those is an error, so a typo is not
// quietly an empty list.
func ParseAllowlist(s string) (Allowlist, error) {
	var a Allowlist
	for _, raw := range strings.Split(s, ",") {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			a.prefixes = append(a.prefixes, unmapPrefix(p).Masked())
			continue
		}
		if ip, err := netip.ParseAddr(e); err == nil {
			ip = ip.Unmap()
			a.prefixes = append(a.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		if strings.ContainsAny(e, "/:") {
			return Allowlist{}, fmt.Errorf("%s: %q is not a CIDR, an IP address or a host name", OutboundAllowlistEnv, raw)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(e, "*."), ".")
		if name == "" || strings.ContainsAny(name, " *") {
			return Allowlist{}, fmt.Errorf("%s: %q is not a CIDR, an IP address or a host name", OutboundAllowlistEnv, raw)
		}
		if strings.HasPrefix(e, "*.") {
			name = "*." + name
		}
		a.hosts = append(a.hosts, name)
	}
	return a, nil
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

// Empty reports whether nothing internal is allowed.
func (a Allowlist) Empty() bool { return len(a.prefixes) == 0 && len(a.hosts) == 0 }

func (a Allowlist) allowsAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (a Allowlist) allowsHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, h := range a.hosts {
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

// special-purpose ranges that are neither loopback, private, link-local nor
// multicast in net/netip's terms and still are not somewhere an organization's
// request belongs.
var special = []struct {
	p      netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "an unspecified address"}, // "this network": 0.x reaches the local host on Linux
	{netip.MustParsePrefix("100.64.0.0/10"), "a shared (carrier-grade NAT) address"},
	{netip.MustParsePrefix("192.0.0.0/24"), "a reserved address"},
	{netip.MustParsePrefix("198.18.0.0/15"), "a reserved address"},
	{netip.MustParsePrefix("240.0.0.0/4"), "a reserved address"}, // includes 255.255.255.255
	{netip.MustParsePrefix("::/96"), "a reserved address"},       // IPv4-compatible, deprecated
	{netip.MustParsePrefix("100::/64"), "a reserved address"},    // discard-only
	{netip.MustParsePrefix("fec0::/10"), "a private address"},    // site-local, deprecated
}

// IPv6 prefixes whose last 32 bits (or, for 6to4, bits 16-47) are an IPv4
// address the packet ends up at: an internal IPv4 address stays internal
// written this way.
var embedsIPv4 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, well-known
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64, local use
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated
}
var sixToFour = netip.MustParsePrefix("2002::/16")

// internalReason says what kind of internal address addr is ("a loopback
// address"), or "" when it is a public one. IPv4-mapped IPv6 addresses are
// judged as the IPv4 address they carry.
func internalReason(addr netip.Addr) string {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return "not a valid address"
	case addr.IsUnspecified():
		return "an unspecified address"
	case addr.IsLoopback():
		return "a loopback address"
	case addr.IsPrivate():
		return "a private address"
	case addr.IsLinkLocalUnicast():
		return "a link-local address"
	case addr.IsMulticast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return "a multicast address"
	}
	for _, s := range special {
		if s.p.Contains(addr) {
			return s.reason
		}
	}
	if addr.Is6() {
		b := addr.As16()
		for _, p := range embedsIPv4 {
			if p.Contains(addr) {
				return internalReason(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
			}
		}
		if sixToFour.Contains(addr) {
			return internalReason(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	return ""
}

// OutboundGuard decides where organization-configured requests may go. Its
// zero value is not usable; build one with NewOutboundGuard.
type OutboundGuard struct {
	allow    Allowlist
	resolver Resolver
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	// proxy is the HTTP(S)_PROXY decision. A proxied request is checked
	// before it is handed over, since the proxy resolves and connects;
	// proxyAddrs are the proxies' own addresses, which DialContext lets
	// through because the operator configured them.
	proxy      func(*http.Request) (*url.URL, error)
	proxyAddrs map[string]bool
	// shared is the guard's transport, built on first use and shared by every
	// Client, so connections are pooled. Each With* copy gets its own.
	shared *sharedTransport
}

type sharedTransport struct {
	once sync.Once
	t    *http.Transport
}

// changed is a copy of g to change a setting of, with a transport of its own.
func (g *OutboundGuard) changed() *OutboundGuard {
	c := *g
	c.shared = &sharedTransport{}
	return &c
}

// NewOutboundGuard builds a guard that allows the public internet and what
// allow names, resolving with the system resolver and honouring
// HTTP_PROXY/HTTPS_PROXY/NO_PROXY.
func NewOutboundGuard(allow Allowlist) *OutboundGuard {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return (&OutboundGuard{
		allow:    allow,
		resolver: net.DefaultResolver,
		dial:     d.DialContext,
	}).WithProxy(http.ProxyFromEnvironment)
}

// WithResolver returns a copy of g that looks names up with r.
func (g *OutboundGuard) WithResolver(r Resolver) *OutboundGuard {
	c := g.changed()
	c.resolver = r
	return c
}

// WithDialer returns a copy of g that opens connections with dial, which is
// handed the address the guard checked.
func (g *OutboundGuard) WithDialer(dial func(ctx context.Context, network, address string) (net.Conn, error)) *OutboundGuard {
	c := g.changed()
	c.dial = dial
	return c
}

// WithProxy returns a copy of g that sends requests through the proxy proxy
// names; nil sends every request directly.
func (g *OutboundGuard) WithProxy(proxy func(*http.Request) (*url.URL, error)) *OutboundGuard {
	c := g.changed()
	c.proxy, c.proxyAddrs = proxy, map[string]bool{}
	if proxy != nil {
		for _, scheme := range []string{"http", "https"} {
			req := &http.Request{URL: &url.URL{Scheme: scheme, Host: "outbound-guard.invalid"}}
			if u, err := proxy(req); err == nil && u != nil {
				c.proxyAddrs[hostPort(u)] = true
			}
		}
	}
	return c
}

var (
	defaultOnce  sync.Once
	defaultGuard *OutboundGuard
	defaultErr   error
)

// DefaultOutboundGuard is the guard built from OIDX_OUTBOUND_ALLOWLIST, once
// per process. When the list does not parse, the guard allows nothing
// internal and the error says why; callers log it.
func DefaultOutboundGuard() (*OutboundGuard, error) {
	defaultOnce.Do(func() {
		// The name is spelled out rather than OutboundAllowlistEnv so that
		// tools/deadconfig, which reads os.Getenv literals, sees what binds
		// the documented setting; the test pins the two to the same string.
		allow, err := ParseAllowlist(os.Getenv("OIDX_OUTBOUND_ALLOWLIST"))
		defaultGuard, defaultErr = NewOutboundGuard(allow), err
	})
	return defaultGuard, defaultErr
}

// CheckURL is the check made when an organization saves a URL: an http or
// https URL whose host is public, or allowlisted. It resolves the name, so a
// name that does not resolve is refused as well.
func (g *OutboundGuard) CheckURL(ctx context.Context, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return &DestinationError{Host: fmt.Sprintf("%q", raw), Reason: "is not an absolute URL"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &DestinationError{Host: u.Hostname(), Reason: "is not reached over http or https"}
	}
	// A name the operator allowlisted is taken on their word, resolvable yet
	// or not; the connection resolves it when there is one to make.
	if g.allow.allowsHost(u.Hostname()) {
		return nil
	}
	_, err = g.addrsFor(ctx, u.Hostname(), "ip")
	return err
}

// addrsFor resolves host and returns its addresses when every one of them may
// be reached, and a DestinationError otherwise. A name with one internal
// address among public ones is refused whole: that shape is how a rebinding
// name hedges, and no receiver needs it.
func (g *OutboundGuard) addrsFor(ctx context.Context, host, network string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if r := internalReason(ip); r != "" && !g.allow.allowsAddr(ip) {
			return nil, &DestinationError{Host: host, Reason: "is " + r}
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	addrs, err := g.resolver.LookupNetIP(ctx, network, host)
	if err != nil || len(addrs) == 0 {
		return nil, &DestinationError{Host: host, Reason: "could not be resolved"}
	}
	if g.allow.allowsHost(host) {
		return addrs, nil
	}
	for _, ip := range addrs {
		if r := internalReason(ip); r != "" && !g.allow.allowsAddr(ip) {
			return nil, &DestinationError{Host: host, Reason: "resolves to " + r}
		}
	}
	return addrs, nil
}

// DialContext opens a connection for an organization-configured request: it
// resolves address's host, refuses it unless every address is allowed, and
// dials the checked addresses themselves, in order.
func (g *OutboundGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g.proxyAddrs[address] {
		return g.dial(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	family := "ip"
	switch network {
	case "tcp4", "udp4":
		family = "ip4"
	case "tcp6", "udp6":
		family = "ip6"
	}
	addrs, err := g.addrsFor(ctx, host, family)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, ip := range addrs {
		conn, err := g.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// proxyFor is the transport's proxy decision. A proxied request is checked
// here, before the proxy resolves and connects on the platform's behalf. A
// direct request aimed at a proxy's own address is refused, because
// DialContext lets that address through.
func (g *OutboundGuard) proxyFor(req *http.Request) (*url.URL, error) {
	if g.proxy == nil {
		return nil, nil
	}
	u, err := g.proxy(req)
	if err != nil {
		return nil, err
	}
	if u == nil {
		if g.proxyAddrs[hostPort(req.URL)] {
			return nil, &DestinationError{Host: req.URL.Hostname(), Reason: "is the outbound proxy"}
		}
		return nil, nil
	}
	if _, err := g.addrsFor(req.Context(), req.URL.Hostname(), "ip"); err != nil {
		return nil, err
	}
	return u, nil
}

// transport is the guard's http.Transport: every connection goes through
// DialContext, and the proxy decision through proxyFor. It is built once per
// guard and shared by the guard's clients.
func (g *OutboundGuard) transport() *http.Transport {
	g.shared.once.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = g.DialContext
		t.DialTLSContext = nil
		t.Proxy = g.proxyFor
		g.shared.t = t
	})
	return g.shared.t
}

// Client is an http.Client for organization-configured URLs: guarded
// connections, the given timeout, and no redirects -- a 3xx is the answer,
// since where it points is up to whoever sent it. A caller that sets
// CheckRedirect back to nil follows redirects, each hop dialed through the
// guard again.
func (g *OutboundGuard) Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: g.transport(),
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// hostPort is u's host and port as the transport dials them, the scheme's
// default port filled in.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
