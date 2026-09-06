package access

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// The headers an upstream receives from a proxy are that upstream's only
// evidence about who is calling it, so on a zero-trust data path they are a
// security boundary. Both proxies here used to build them with a Director,
// and the standard library's Director path does two things that are easy to
// miss when reading the handler:
//
//   - it never deletes the CLIENT'S Forwarded / X-Forwarded-Host /
//     X-Forwarded-Proto headers, so they reach the upstream verbatim, and
//   - it folds the client's X-Forwarded-For into the outbound one.
//
// A request carrying "X-Forwarded-For: 9.9.9.9, X-Forwarded-Host:
// evil.example.com" therefore arrived upstream with evil.example.com intact,
// and (through the Ziti overlay proxy) with 9.9.9.9 as the leftmost
// X-Forwarded-For entry — which is exactly the entry an upstream reads when
// it wants "the real client".
//
// These tests send that request and assert on what the upstream actually
// sees. They are written against the real httputil.ReverseProxy rather than
// by calling the rewrite hook directly, because half of the behaviour under
// test belongs to the library around the hook.

// spoofed is the request a hostile client sends: every forwarding header
// filled in with a lie.
func spoofedRequest(t *testing.T, frontendURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", frontendURL+"/api/thing?a=1", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = "public.example.com"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=9.9.9.9;host=evil.example.com")
	return req
}

// runThrough serves proxy on a test frontend, sends req, and returns what the
// upstream saw.
type upstreamView struct {
	header http.Header
	host   string
	path   string
	query  string
}

func runThrough(t *testing.T, newProxy func(target *url.URL) *httputil.ReverseProxy, makeReq func(frontendURL string) *http.Request) upstreamView {
	t.Helper()
	var seen upstreamView
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = upstreamView{
			header: r.Header.Clone(),
			host:   r.Host,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
		}
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parsing upstream url: %v", err)
	}
	frontend := httptest.NewServer(newProxy(target))
	defer frontend.Close()

	resp, err := http.DefaultClient.Do(makeReq(frontend.URL))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()
	return seen
}

// TestProxyRewriteDropsClientForwardingClaims is the regression test for the
// defect: nothing the caller asserted about its own provenance may survive.
func TestProxyRewriteDropsClientForwardingClaims(t *testing.T) {
	route := &ProxyRoute{Name: "app", CustomHeaders: map[string]string{}}
	session := &ProxySession{UserID: "u-1", Email: "a@b.test", Name: "A B", Roles: []string{"admin", "dev"}}

	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, session, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request { return spoofedRequest(t, frontendURL) },
	)

	// X-Forwarded-For must be the address this proxy resolved, exactly once.
	// Under Director this read "203.0.113.7, 127.0.0.1" — the library appended
	// the peer to what the handler had already Set.
	if got := seen.header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "203.0.113.7")
	}
	if strings.Contains(seen.header.Get("X-Forwarded-For"), "9.9.9.9") {
		t.Error("the caller's claimed X-Forwarded-For reached the upstream")
	}

	// The spoofed host claim must be replaced by the host this proxy was
	// actually asked for, not passed through.
	if got := seen.header.Get("X-Forwarded-Host"); got != "public.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "public.example.com")
	}

	// Forwarded is not re-set at all, so it must be absent rather than the
	// caller's version.
	if got := seen.header.Get("Forwarded"); got != "" {
		t.Errorf("Forwarded = %q, want it dropped", got)
	}

	// Plain HTTP inbound: the claim of https must not survive.
	if got := seen.header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := seen.header.Get("X-Real-Ip"); got != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want %q", got, "203.0.113.7")
	}
}

// TestProxyRewriteStripsOverlayIdentityClaim pins a header this proxy never
// writes but must still delete: X-Ziti-Identity is set by the overlay proxy,
// so an upstream reachable by both paths treats it as authenticated fact. A
// caller reaching that upstream through a route must not be able to type it.
func TestProxyRewriteStripsOverlayIdentityClaim(t *testing.T) {
	route := &ProxyRoute{Name: "app"}
	session := &ProxySession{UserID: "u-1"}

	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, session, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request {
			req := spoofedRequest(t, frontendURL)
			req.Header.Set("X-Ziti-Identity", "somebody-else")
			return req
		},
	)
	if got := seen.header.Get("X-Ziti-Identity"); got != "" {
		t.Errorf("X-Ziti-Identity = %q, want it stripped", got)
	}
}

// TestProxyRewriteInjectsVerifiedIdentity pins that the identity an upstream
// authorizes against comes from the session, and that a route without auth
// sends no identity at all rather than an empty one.
func TestProxyRewriteInjectsVerifiedIdentity(t *testing.T) {
	route := &ProxyRoute{Name: "app"}
	session := &ProxySession{UserID: "u-1", Email: "a@b.test", Name: "A B", Roles: []string{"admin", "dev"}}

	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, session, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request {
			// A caller that tries to name itself must not be believed either.
			req := spoofedRequest(t, frontendURL)
			req.Header.Set("X-Forwarded-User", "root")
			req.Header.Set("X-Forwarded-Roles", "superadmin")
			return req
		},
	)

	for header, want := range map[string]string{
		"X-Forwarded-User":  "u-1",
		"X-Forwarded-Email": "a@b.test",
		"X-Forwarded-Name":  "A B",
		"X-Forwarded-Roles": "admin,dev",
	} {
		if got := seen.header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	// No session: the upstream must not receive a spoofed identity from the
	// request either. These headers are not in the library's delete list, so
	// this is the hook's own responsibility — it overwrites them when a
	// session exists, and an unauthenticated route must not let the caller's
	// version through.
	seenAnon := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, nil, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request {
			req := spoofedRequest(t, frontendURL)
			req.Header.Set("X-Forwarded-User", "root")
			return req
		},
	)
	if got := seenAnon.header.Get("X-Forwarded-User"); got != "" {
		t.Errorf("X-Forwarded-User = %q: the caller named itself on an "+
			"unauthenticated route and the upstream believed it", got)
	}
}

// TestProxyRewritePreserveHost pins both sides of the route toggle, because
// getting it backwards silently changes which virtual host an upstream serves.
func TestProxyRewritePreserveHost(t *testing.T) {
	session := &ProxySession{UserID: "u-1"}

	preserving := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			route := &ProxyRoute{Name: "app", PreserveHost: true}
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, session, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request { return spoofedRequest(t, frontendURL) },
	)
	if preserving.host != "public.example.com" {
		t.Errorf("preserve_host: upstream Host = %q, want the inbound host", preserving.host)
	}

	rewriting := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			route := &ProxyRoute{Name: "app"}
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, session, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request { return spoofedRequest(t, frontendURL) },
	)
	if rewriting.host == "public.example.com" {
		t.Error("preserve_host off: the inbound host reached the upstream anyway")
	}
}

// TestProxyRewriteCustomHeadersWinLast pins the ordering an operator relies
// on: a route's custom headers are applied after the generated ones, so a
// deployment can deliberately override them.
func TestProxyRewriteCustomHeadersWinLast(t *testing.T) {
	route := &ProxyRoute{
		Name:          "app",
		CustomHeaders: map[string]string{"X-Tenant": "acme", "X-Real-IP": "10.0.0.1"},
	}

	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: proxyRewrite(target, route, nil, "203.0.113.7")}
		},
		func(frontendURL string) *http.Request { return spoofedRequest(t, frontendURL) },
	)
	if got := seen.header.Get("X-Tenant"); got != "acme" {
		t.Errorf("X-Tenant = %q, want %q", got, "acme")
	}
	if got := seen.header.Get("X-Real-Ip"); got != "10.0.0.1" {
		t.Errorf("X-Real-IP = %q, want the route's override %q", got, "10.0.0.1")
	}
}

// TestProxyRewriteJoinsUpstreamPath pins that the upstream's own path prefix
// is prepended and the query survives, which is what singleJoiningSlash is
// for. A regression here would silently route every request to the wrong
// upstream path.
func TestProxyRewriteJoinsUpstreamPath(t *testing.T) {
	var seen upstreamView
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = upstreamView{path: r.URL.Path, query: r.URL.RawQuery}
	}))
	defer upstream.Close()

	// Give the target a path prefix, which httptest's URL does not have.
	target, err := url.Parse(upstream.URL + "/backend")
	if err != nil {
		t.Fatalf("parsing upstream url: %v", err)
	}
	route := &ProxyRoute{Name: "app"}
	frontend := httptest.NewServer(&httputil.ReverseProxy{
		Rewrite: proxyRewrite(target, route, nil, "203.0.113.7"),
	})
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/api/thing?a=1&b=2")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()

	if seen.path != "/backend/api/thing" {
		t.Errorf("upstream path = %q, want %q", seen.path, "/backend/api/thing")
	}
	if seen.query != "a=1&b=2" {
		t.Errorf("upstream query = %q, want %q", seen.query, "a=1&b=2")
	}
}

// TestZitiProxyRewriteDropsClientForwardingClaims is the same regression on
// the overlay proxy, where it mattered most: that Director wrapped the
// library's own, so the caller's X-Forwarded-For was not merely passed
// through but promoted to the LEFTMOST entry — the one an upstream reads as
// the real client address.
func TestZitiProxyRewriteDropsClientForwardingClaims(t *testing.T) {
	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{
				Rewrite: zitiProxyRewrite(target, "user-42", "u@42.test", "User Fortytwo", "admin,dev"),
			}
		},
		func(frontendURL string) *http.Request {
			req := spoofedRequest(t, frontendURL)
			req.Header.Set("X-Ziti-Identity", "somebody-else")
			return req
		},
	)

	xff := seen.header.Get("X-Forwarded-For")
	if strings.Contains(xff, "9.9.9.9") {
		t.Errorf("X-Forwarded-For = %q: the caller's claim survived, and it is "+
			"the leftmost entry an upstream reads as the client", xff)
	}
	if xff == "" {
		t.Error("X-Forwarded-For was dropped entirely; the overlay peer should still be reported")
	}
	if got := seen.header.Get("X-Forwarded-Host"); got != "" {
		t.Errorf("X-Forwarded-Host = %q, want it dropped rather than the caller's claim", got)
	}
	if got := seen.header.Get("Forwarded"); got != "" {
		t.Errorf("Forwarded = %q, want it dropped", got)
	}
	// Deliberately not asserted by this hop: see zitiProxyRewrite's comment.
	if got := seen.header.Get("X-Forwarded-Proto"); got != "" {
		t.Errorf("X-Forwarded-Proto = %q, want it unset on an overlay hop", got)
	}

	// The enrolled identity replaces whatever the caller claimed.
	for header, want := range map[string]string{
		"X-Ziti-Identity":   "user-42",
		"X-Forwarded-User":  "user-42",
		"X-Forwarded-Email": "u@42.test",
		"X-Forwarded-Name":  "User Fortytwo",
		"X-Forwarded-Roles": "admin,dev",
	} {
		if got := seen.header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// TestZitiProxyRewriteKeepsInboundHost pins the one thing SetURL changes that
// the old Director did not: it clears Out.Host. A name-based virtual host
// upstream would start serving the wrong site if that reached production.
func TestZitiProxyRewriteKeepsInboundHost(t *testing.T) {
	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: zitiProxyRewrite(target, "", "", "", "")}
		},
		func(frontendURL string) *http.Request { return spoofedRequest(t, frontendURL) },
	)
	if seen.host != "public.example.com" {
		t.Errorf("upstream Host = %q, want the inbound host preserved", seen.host)
	}
}

// TestZitiProxyRewriteAnonymousSendsNoIdentity pins that a connection with no
// resolved Ziti identity cannot borrow one from the request headers.
func TestZitiProxyRewriteAnonymousSendsNoIdentity(t *testing.T) {
	seen := runThrough(t,
		func(target *url.URL) *httputil.ReverseProxy {
			return &httputil.ReverseProxy{Rewrite: zitiProxyRewrite(target, "", "", "", "")}
		},
		func(frontendURL string) *http.Request {
			req := spoofedRequest(t, frontendURL)
			req.Header.Set("X-Ziti-Identity", "root")
			req.Header.Set("X-Forwarded-User", "root")
			return req
		},
	)
	if got := seen.header.Get("X-Ziti-Identity"); got != "" {
		t.Errorf("X-Ziti-Identity = %q: an unidentified overlay connection let "+
			"the caller name itself", got)
	}
	if got := seen.header.Get("X-Forwarded-User"); got != "" {
		t.Errorf("X-Forwarded-User = %q: same, via the other header an upstream "+
			"reads as authenticated fact", got)
	}
}
