package netutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// WHERE AN ORGANIZATION'S URL MAY SEND THE PLATFORM.
//
// Webhook subscriptions, audit-stream webhooks, outbound SCIM targets, SSF
// receivers and SAML metadata URLs are typed in by an organization's
// administrator and requested from inside the platform's network. These tests
// hold the guard those requests go through to its three promises:
//
//   - every spelling of an internal address is refused, and a public one is
//     not (the classification table);
//   - the check is made again at the connection, and the connection goes to
//     the address that was checked, so a name that resolves somewhere public
//     when it is saved and somewhere internal when it is used is refused;
//   - a redirect is the answer, not an instruction.
//
// A fake resolver stands in for DNS, and a fake "internet" dialer delivers a
// connection for a made-up public address to a local test server, the way the
// real network would deliver it to the receiver. Every other address is
// dialed for real, so a check that is skipped reaches the internal server and
// the test sees it.

// resolver answers from a table. A name with several answers gives them in
// turn, the last one repeating: that is a rebinding name.
type resolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups map[string]int
}

func newResolver(answers map[string][]string) *resolver {
	return &resolver{answers: answers, lookups: map[string]int{}}
}

func (r *resolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := r.lookups[host]
	r.lookups[host]++
	if i >= len(seq) {
		i = len(seq) - 1
	}
	var out []netip.Addr
	for _, a := range strings.Split(seq[i], ",") {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func (r *resolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups[host]
}

// internet routes made-up public addresses to local servers and records every
// address it was asked to dial. A name it is handed is resolved through dns,
// as a system dialer would resolve it, and anything it has no route for is
// dialed as is: a guard that skipped its check would reach whatever the name
// resolves to now.
type internet struct {
	mu     sync.Mutex
	dns    *resolver
	routes map[string]string // "203.0.113.10:443" -> "127.0.0.1:41234"
	dialed []string
}

func (n *internet) route(publicAddr string, srv *httptest.Server) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.routes == nil {
		n.routes = map[string]string{}
	}
	n.routes[publicAddr] = srv.Listener.Addr().String()
}

func (n *internet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(address); err == nil && n.dns != nil {
		if _, perr := netip.ParseAddr(host); perr != nil {
			addrs, lerr := n.dns.LookupNetIP(ctx, "ip", host)
			if lerr != nil {
				return nil, lerr
			}
			address = net.JoinHostPort(addrs[0].String(), port)
		}
	}
	n.mu.Lock()
	n.dialed = append(n.dialed, address)
	to, ok := n.routes[address]
	n.mu.Unlock()
	if ok {
		address = to
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (n *internet) dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

// counter is a test server that counts what reaches it.
type counter struct {
	hits atomic.Int64
	srv  *httptest.Server
}

func newCounter(t *testing.T, h http.HandlerFunc) *counter {
	t.Helper()
	c := &counter{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		_, _ = io.WriteString(w, "internal secret")
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *counter) port() string {
	_, p, _ := net.SplitHostPort(c.srv.Listener.Addr().String())
	return p
}

func guardFor(t *testing.T, allow string, r Resolver, n *internet) *OutboundGuard {
	t.Helper()
	a, err := ParseAllowlist(allow)
	if err != nil {
		t.Fatalf("ParseAllowlist(%q): %v", allow, err)
	}
	// No proxy: the test's own environment must not decide where requests go.
	g := NewOutboundGuard(a).WithProxy(nil).WithResolver(r)
	if n != nil {
		g = g.WithDialer(n.dial)
	}
	return g
}

func mustRefuse(t *testing.T, err error, wantReason string) *DestinationError {
	t.Helper()
	var de *DestinationError
	if !errors.As(err, &de) {
		t.Fatalf("want a refused destination (%s), got %v", wantReason, err)
	}
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("%v does not wrap ErrDestinationNotAllowed", err)
	}
	if !strings.Contains(de.Reason, wantReason) {
		t.Errorf("refused as %q, want a reason naming %q", de.Reason, wantReason)
	}
	return de
}

func TestEverySpellingOfAnInternalAddressIsRefusedAndPublicOnesAreNot(t *testing.T) {
	internal := map[string]string{
		"127.0.0.1":          "loopback",
		"127.255.255.254":    "loopback",
		"::1":                "loopback",
		"10.0.0.1":           "private",
		"172.16.0.1":         "private",
		"172.31.0.1":         "private",
		"192.168.1.1":        "private",
		"fc00::1":            "private", // unique local
		"fd12:3456:789a::1":  "private",
		"fec0::1":            "private", // site-local, deprecated
		"169.254.169.254":    "link-local",
		"fe80::1":            "link-local",
		"fe80::1%eth0":       "link-local",
		"100.64.0.1":         "shared",
		"100.127.255.254":    "shared",
		"0.0.0.0":            "unspecified",
		"0.1.2.3":            "unspecified",
		"::":                 "unspecified",
		"224.0.0.1":          "multicast",
		"239.255.255.250":    "multicast",
		"ff02::1":            "multicast",
		"ff05::2":            "multicast",
		"255.255.255.255":    "reserved",
		"240.0.0.1":          "reserved",
		"198.18.0.1":         "reserved",
		"192.0.0.170":        "reserved",
		"100::1":             "reserved",
		"::127.0.0.1":        "reserved", // IPv4-compatible, deprecated
		"::ffff:127.0.0.1":   "loopback", // IPv4-mapped
		"::ffff:10.0.0.1":    "private",
		"::ffff:100.64.0.1":  "shared", // mapped, in a range net/netip has no predicate for
		"::ffff:0.0.0.1":     "unspecified",
		"::ffff:a9fe:a9fe":   "link-local", // 169.254.169.254, mapped, in hex
		"::ffff:0:a00:1":     "private",    // IPv4-translated 10.0.0.1
		"64:ff9b::a9fe:a9fe": "link-local", // NAT64 of 169.254.169.254
		"64:ff9b::7f00:1":    "loopback",
		"64:ff9b:1::a00:1":   "private", // local-use NAT64 of 10.0.0.1
		"2002:a9fe:a9fe::1":  "link-local",
		"2002:7f00:1::1":     "loopback", // 6to4 of 127.0.0.1
		"2002:c0a8:101::1":   "private",  // 6to4 of 192.168.1.1
	}
	for s, want := range internal {
		if got := internalReason(netip.MustParseAddr(s)); !strings.Contains(got, want) {
			t.Errorf("%s is judged %q, want an internal address of kind %q", s, got, want)
		}
		if !isPrivateIP(net.ParseIP(strings.Split(s, "%")[0])) {
			t.Errorf("isPrivateIP(%s) = false: the SSRF validator and the dial-time guard disagree", s)
		}
	}

	public := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.10",
		"172.32.0.1",  // just past 172.16.0.0/12
		"100.128.0.1", // just past 100.64.0.0/10
		"198.20.0.1",  // just past 198.18.0.0/15
		"192.0.1.1",   // just past 192.0.0.0/24
		"2001:4860:4860::8888",
		"::ffff:8.8.8.8",
		"64:ff9b::808:808", // NAT64 of 8.8.8.8
		"2002:808:808::1",  // 6to4 of 8.8.8.8
	}
	for _, s := range public {
		if got := internalReason(netip.MustParseAddr(s)); got != "" {
			t.Errorf("%s is judged %q; it is a public address and must stay reachable", s, got)
		}
		if isPrivateIP(net.ParseIP(s)) {
			t.Errorf("isPrivateIP(%s) = true for a public address", s)
		}
	}
}

func TestTheAllowlistParsesCIDRsAddressesAndNamesAndRejectsTypos(t *testing.T) {
	a, err := ParseAllowlist(" 10.0.0.0/25, 192.168.1.7 ,hooks.corp.example., *.svc.cluster.local, ::ffff:172.16.0.0/112 ,, fd00:1::/32")
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	for _, s := range []string{"10.0.0.4", "::ffff:10.0.0.4", "192.168.1.7", "172.16.0.9", "fd00:1::5"} {
		if !a.allowsAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s is not allowed, want allowed", s)
		}
	}
	for _, s := range []string{"10.0.0.200", "192.168.1.8", "172.17.0.1", "fd00:2::5", "127.0.0.1"} {
		if a.allowsAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s is allowed, want refused", s)
		}
	}
	for _, h := range []string{"hooks.corp.example", "HOOKS.corp.example.", "a.svc.cluster.local", "b.a.svc.cluster.local"} {
		if !a.allowsHost(h) {
			t.Errorf("host %s is not allowed, want allowed", h)
		}
	}
	for _, h := range []string{"svc.cluster.local", "evil-svc.cluster.local", "hooks.corp.example.evil.test", "corp.example"} {
		if a.allowsHost(h) {
			t.Errorf("host %s is allowed, want refused", h)
		}
	}

	if empty, err := ParseAllowlist(""); err != nil || !empty.Empty() {
		t.Errorf("the default (empty) allowlist = %+v, %v; want one that allows nothing", empty, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "http://hooks.corp.example", "*", "*.", "exa mple.test", "hooks/path", "fe80::1::2"} {
		if _, err := ParseAllowlist("10.0.0.0/8," + bad); err == nil {
			t.Errorf("ParseAllowlist accepted %q; a typo must not quietly become a narrower list", bad)
		} else if !strings.Contains(err.Error(), OutboundAllowlistEnv) {
			t.Errorf("the error for %q does not name %s: %v", bad, OutboundAllowlistEnv, err)
		}
	}
}

func TestAURLNamingOrResolvingToAnInternalAddressIsRefusedWhenSaved(t *testing.T) {
	r := newResolver(map[string][]string{
		"hooks.example.test":    {"203.0.113.10"},
		"metadata.example.test": {"169.254.169.254"},
		"hedged.example.test":   {"203.0.113.10,10.0.0.5"},
		"v6.example.test":       {"2001:db8::1,::ffff:127.0.0.1"},
	})
	g := guardFor(t, "", r, nil)
	ctx := context.Background()

	if err := g.CheckURL(ctx, "https://hooks.example.test/hook"); err != nil {
		t.Fatalf("a public destination was refused: %v", err)
	}
	mustRefuse(t, g.CheckURL(ctx, "https://127.0.0.1:8443/hook"), "loopback")
	mustRefuse(t, g.CheckURL(ctx, "http://[::ffff:169.254.169.254]/latest/meta-data/"), "link-local")
	mustRefuse(t, g.CheckURL(ctx, "http://0.0.0.0:8005/api/v1/users"), "unspecified")
	mustRefuse(t, g.CheckURL(ctx, "https://hedged.example.test/"), "private")
	mustRefuse(t, g.CheckURL(ctx, "https://v6.example.test/"), "loopback")
	mustRefuse(t, g.CheckURL(ctx, "https://nowhere.example.test/"), "could not be resolved")
	mustRefuse(t, g.CheckURL(ctx, "gopher://hooks.example.test/"), "http or https")
	mustRefuse(t, g.CheckURL(ctx, "hooks.example.test/hook"), "absolute URL")

	// What the administrator is told names what they typed and the kind of
	// address, never the address the platform's resolver gave: that would map
	// the internal network for them one name at a time.
	de := mustRefuse(t, g.CheckURL(ctx, "https://metadata.example.test/latest"), "resolves to a link-local address")
	if strings.Contains(de.Error(), "169.254") {
		t.Errorf("the refusal %q discloses the resolved address", de.Error())
	}
}

func TestTheOperatorsAllowlistLetsNamedInternalDestinationsThrough(t *testing.T) {
	r := newResolver(map[string][]string{
		"hooks.corp.example": {"10.0.0.99"}, // outside the CIDR: allowed by name
		"svc.corp.example":   {"10.0.0.20"},
		"other.corp.example": {"10.0.0.70"},
	})
	g := guardFor(t, "10.0.0.0/26, hooks.corp.example", r, nil)
	ctx := context.Background()

	for _, u := range []string{"https://10.0.0.30/", "https://svc.corp.example/", "https://hooks.corp.example/"} {
		if err := g.CheckURL(ctx, u); err != nil {
			t.Errorf("%s is allowlisted and was refused: %v", u, err)
		}
	}
	if n := r.count("hooks.corp.example"); n != 0 {
		t.Errorf("an allowlisted name was resolved %d times at save time; it is taken on the operator's word", n)
	}
	mustRefuse(t, g.CheckURL(ctx, "https://other.corp.example/"), "private")
	mustRefuse(t, g.CheckURL(ctx, "https://127.0.0.1/"), "loopback")
}

// THE REBINDING NAME. It resolves somewhere public when the URL is saved, and
// to the platform's own loopback when the request is made. The connection
// must be refused, and the internal server must not see it.
func TestANameThatResolvesInternallyAtConnectionTimeIsRefused(t *testing.T) {
	internal := newCounter(t, nil)
	r := newResolver(map[string][]string{
		"rebind.example.test": {"203.0.113.10", "127.0.0.1"},
	})
	n := &internet{dns: r}
	g := guardFor(t, "", r, n)
	ctx := context.Background()
	u := "http://rebind.example.test:" + internal.port() + "/secret"

	if err := g.CheckURL(ctx, u); err != nil {
		t.Fatalf("at save time the name is public: %v", err)
	}
	resp, err := g.Client(5 * time.Second).Get(u)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("the request reached %s (status %d) after the name moved to loopback", u, resp.StatusCode)
	}
	mustRefuse(t, err, "resolves to a loopback address")
	if got := internal.hits.Load(); got != 0 {
		t.Errorf("the internal server was reached %d times", got)
	}
	if d := n.dials(); len(d) != 0 {
		t.Errorf("the guard dialed %v; a refused name must not be dialed at all", d)
	}
}

// The connection goes to the address that was checked. The name is not
// handed to the dialer to resolve a second time.
func TestAPublicDestinationIsReachedAtTheAddressThatWasChecked(t *testing.T) {
	receiver := newCounter(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	r := newResolver(map[string][]string{"hooks.example.test": {"203.0.113.10"}})
	n := &internet{dns: r}
	n.route("203.0.113.10:80", receiver.srv)
	g := guardFor(t, "", r, n)

	resp, err := g.Client(5*time.Second).Post("http://hooks.example.test/hook", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("a public destination was refused: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" || receiver.hits.Load() != 1 {
		t.Fatalf("got %d %q with %d hits, want the receiver's 200 ok once", resp.StatusCode, body, receiver.hits.Load())
	}
	if d := n.dials(); len(d) != 1 || d[0] != "203.0.113.10:80" {
		t.Errorf("dialed %v, want exactly the checked address 203.0.113.10:80", d)
	}
}

// A 3xx is the answer. Following it would let whoever answers choose the next
// destination -- an internal one, or another public one that was never
// checked when the URL was saved.
func TestARedirectIsNotFollowed(t *testing.T) {
	internal := newCounter(t, nil)
	elsewhere := newCounter(t, nil)
	r := newResolver(map[string][]string{
		"hooks.example.test":     {"203.0.113.10"},
		"elsewhere.example.test": {"203.0.113.20"},
	})
	n := &internet{dns: r}
	n.route("203.0.113.20:80", elsewhere.srv)
	for _, target := range []string{
		"http://127.0.0.1:" + internal.port() + "/latest/meta-data/",
		"http://elsewhere.example.test/",
	} {
		t.Run(target, func(t *testing.T) {
			redirector := newCounter(t, func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, target, http.StatusTemporaryRedirect)
			})
			n.route("203.0.113.10:80", redirector.srv)
			g := guardFor(t, "", r, n)

			resp, err := g.Client(5*time.Second).Post("http://hooks.example.test/hook", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatalf("the redirect itself is the answer, got an error: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Errorf("status %d, want the 307 itself", resp.StatusCode)
			}
			if internal.hits.Load() != 0 || elsewhere.hits.Load() != 0 {
				t.Errorf("the redirect was followed: internal=%d elsewhere=%d", internal.hits.Load(), elsewhere.hits.Load())
			}
		})
	}
}

// A caller that does follow redirects (the SAML metadata fetch does) gets
// every hop checked at its connection.
func TestEachFollowedRedirectIsCheckedAtItsConnection(t *testing.T) {
	internal := newCounter(t, nil)
	r := newResolver(map[string][]string{"md.example.test": {"203.0.113.10"}})
	n := &internet{dns: r}
	redirector := newCounter(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://127.0.0.1:"+internal.port()+"/", http.StatusFound)
	})
	n.route("203.0.113.10:80", redirector.srv)
	c := guardFor(t, "", r, n).Client(5 * time.Second)
	c.CheckRedirect = nil

	resp, err := c.Get("http://md.example.test/metadata")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("the redirect to loopback was followed (status %d)", resp.StatusCode)
	}
	mustRefuse(t, err, "loopback")
	if internal.hits.Load() != 0 {
		t.Errorf("the internal server was reached %d times", internal.hits.Load())
	}
}

func TestAnAllowlistedInternalDestinationIsReached(t *testing.T) {
	internal := newCounter(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") })
	r := newResolver(map[string][]string{"hooks.corp.example": {"127.0.0.1"}})
	for _, allow := range []string{"127.0.0.0/8", "hooks.corp.example"} {
		t.Run(allow, func(t *testing.T) {
			g := guardFor(t, allow, r, nil)
			u := "http://hooks.corp.example:" + internal.port() + "/"
			if err := g.CheckURL(context.Background(), u); err != nil {
				t.Fatalf("allowlisted by %q and refused at save time: %v", allow, err)
			}
			resp, err := g.Client(5 * time.Second).Get(u)
			if err != nil {
				t.Fatalf("allowlisted by %q and refused at the connection: %v", allow, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "hello" {
				t.Errorf("got %q", body)
			}
		})
	}
	before := internal.hits.Load()
	g := guardFor(t, "10.0.0.0/8", r, nil)
	if resp, err := g.Client(5 * time.Second).Get("http://hooks.corp.example:" + internal.port() + "/"); err == nil {
		resp.Body.Close()
		t.Error("an allowlist naming other addresses let loopback through")
	}
	if internal.hits.Load() != before {
		t.Error("the internal server was reached without an allowlist entry for it")
	}
}

// Behind an HTTP proxy the proxy resolves and connects, so the destination is
// checked before the request is handed to it, and the proxy's own address --
// which the guard must let through, since the operator configured it -- is
// not reachable as a destination.
func TestBehindAProxyTheDestinationIsCheckedAndTheProxyIsNotADestination(t *testing.T) {
	var proxied []string
	var mu sync.Mutex
	proxy := newCounter(t, func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		proxied = append(proxied, req.URL.String())
		mu.Unlock()
		_, _ = io.WriteString(w, "via proxy")
	})
	proxyURL, _ := url.Parse(proxy.srv.URL)
	r := newResolver(map[string][]string{
		"hooks.example.test":    {"203.0.113.10"},
		"internal.example.test": {"10.0.0.8"},
	})
	a, _ := ParseAllowlist("")
	g := NewOutboundGuard(a).WithResolver(r).WithProxy(func(req *http.Request) (*url.URL, error) {
		// Loopback is never proxied, as with http.ProxyFromEnvironment.
		if req.URL.Hostname() == "127.0.0.1" {
			return nil, nil
		}
		return proxyURL, nil
	})
	c := g.Client(5 * time.Second)

	resp, err := c.Get("http://hooks.example.test/hook")
	if err != nil {
		t.Fatalf("a public destination behind the proxy was refused: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via proxy" {
		t.Fatalf("got %q, want the proxy's answer", body)
	}

	_, err = c.Get("http://internal.example.test/")
	mustRefuse(t, err, "private")
	_, err = c.Get(proxy.srv.URL + "/")
	mustRefuse(t, err, "outbound proxy")

	mu.Lock()
	defer mu.Unlock()
	if len(proxied) != 1 || !strings.Contains(proxied[0], "hooks.example.test") {
		t.Errorf("the proxy was handed %v, want only the public destination", proxied)
	}
	if got := proxy.hits.Load(); got != 1 {
		t.Errorf("the proxy was reached %d times, want once", got)
	}
}

// DefaultOutboundGuard spells the variable out for tools/deadconfig; the
// constant the errors and hints name must be the same string.
func TestTheAllowlistVariableIsTheOneDefaultOutboundGuardReads(t *testing.T) {
	if OutboundAllowlistEnv != "OIDX_OUTBOUND_ALLOWLIST" {
		t.Errorf("OutboundAllowlistEnv = %q, but DefaultOutboundGuard reads OIDX_OUTBOUND_ALLOWLIST", OutboundAllowlistEnv)
	}
}

func TestTheDestinationErrorReadsAsASentence(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &DestinationError{Host: "hooks.example.test", Reason: "resolves to a private address"})
	if got := err.Error(); got != "wrapped: hooks.example.test resolves to a private address" {
		t.Errorf("got %q", got)
	}
}
