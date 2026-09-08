package middleware

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestConfigureTrustedProxies_IgnoresSpoofedLeftmostXFF is the security
// regression: with only loopback trusted, a client-supplied leftmost
// X-Forwarded-For entry must NOT be honored as the client IP. gin should resolve
// the rightmost untrusted address (the real remote_addr the edge saw).
func TestConfigureTrustedProxies_IgnoresSpoofedLeftmostXFF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "") // use secure loopback default

	r := gin.New()
	ConfigureTrustedProxies(r, nil)

	var got string
	r.GET("/ip", func(c *gin.Context) {
		got = c.ClientIP()
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	// Simulate the edge (loopback) appending the real client IP after the
	// attacker's spoofed value: attacker sent 198.51.100.7, real remote is 203.0.113.9.
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
	req.RemoteAddr = "127.0.0.1:12345" // connection comes from the trusted edge
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got == "198.51.100.7" {
		t.Fatalf("spoofed leftmost X-Forwarded-For was honored as client IP (got %q); auto-approve/geo-block bypass", got)
	}
	if got != "203.0.113.9" {
		t.Fatalf("expected real client IP 203.0.113.9, got %q", got)
	}
}

// TestConfigureTrustedProxies_UntrustedDirectClientNotSpoofable verifies that a
// direct (non-loopback) caller cannot inject a client IP at all: gin falls back
// to the real RemoteAddr and ignores the header.
func TestConfigureTrustedProxies_UntrustedDirectClientNotSpoofable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "")

	r := gin.New()
	ConfigureTrustedProxies(r, nil)

	var got string
	r.GET("/ip", func(c *gin.Context) {
		got = c.ClientIP()
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.RemoteAddr = "198.51.100.7:9999" // untrusted direct client
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got != "198.51.100.7" {
		t.Fatalf("untrusted client should resolve to RemoteAddr 198.51.100.7, got %q", got)
	}
}

// The two tests above prove the control is not BYPASSABLE. Neither asks whether
// it is USABLE, and the second hides the answer by giving the attacker the same
// address in RemoteAddr and X-Forwarded-For, so the right answer and the wrong
// one are the same string.
//
// This one separates them. A proxy at 172.18.0.9 forwards a client at
// 203.0.113.7 — the shape of deployments/docker (nginx `proxy_pass
// http://oauth-service:8006`) and of an ingress pod forwarding to a service pod.
// Under the loopback default the service answers "172.18.0.9" and the client's
// address is gone.
func TestClientIPBehindANonLoopbackProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const realClient = "203.0.113.7"
	const containerHop = "172.18.0.9"

	cases := []struct {
		name       string
		trustedEnv string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "loopback hop: the premise the default was written for",
			remoteAddr: "127.0.0.1:5555",
			xff:        realClient,
			want:       realClient,
		},
		{
			// The finding. Nothing is misconfigured in nginx: it wrote the
			// client's address into X-Forwarded-For exactly as it should.
			name:       "container hop: the client's address is discarded",
			remoteAddr: containerHop + ":5555",
			xff:        realClient,
			want:       containerHop,
		},
		{
			name:       "container hop with a full chain: still discarded",
			remoteAddr: containerHop + ":5555",
			xff:        realClient + ", " + containerHop,
			want:       containerHop,
		},
		{
			// And the fix, from the same table so the two are read together.
			name:       "container hop, hop trusted: the client resolves",
			trustedEnv: "127.0.0.1/32,::1/128,172.18.0.0/16",
			remoteAddr: containerHop + ":5555",
			xff:        realClient,
			want:       realClient,
		},
		{
			// Trusting the hop does not re-open the spoof: the leftmost entry is
			// still the attacker's, and the rightmost untrusted one still wins.
			name:       "container hop trusted, spoofed leftmost entry: still ignored",
			trustedEnv: "127.0.0.1/32,::1/128,172.18.0.0/16",
			remoteAddr: containerHop + ":5555",
			xff:        "198.51.100.7, " + realClient,
			want:       realClient,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OIDX_TRUSTED_PROXIES", tc.trustedEnv)

			r := gin.New()
			ConfigureTrustedProxies(r, nil)

			var got string
			r.GET("/ip", func(c *gin.Context) {
				got = c.ClientIP()
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set("X-Forwarded-For", tc.xff)
			r.ServeHTTP(httptest.NewRecorder(), req)

			if got != tc.want {
				t.Fatalf("remote=%s xff=%q trusted=%q: ClientIP=%q, want %q",
					tc.remoteAddr, tc.xff, tc.trustedEnv, got, tc.want)
			}
		})
	}
}

// The default cannot be widened without trusting a forwarded header on installs
// whose services are directly reachable, so what has to change is that the
// mismatch stops being silent. One line per hop, naming the address to add.
func TestForwardedFromAnUntrustedHopIsReported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "")

	core, logs := observer.New(zap.WarnLevel)
	r := gin.New()
	ConfigureTrustedProxies(r, zap.New(core))
	r.GET("/ip", func(c *gin.Context) { c.Status(http.StatusOK) })

	before := counterValue(t, forwardedFromUntrustedHopTotal)

	send := func(remoteAddr string, headers map[string]string) {
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		req.RemoteAddr = remoteAddr
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	xff := map[string]string{"X-Forwarded-For": "203.0.113.7"}

	// Three requests from the same untrusted hop: one warning, three counts.
	send("172.18.0.9:1", xff)
	send("172.18.0.9:2", xff)
	send("172.18.0.9:3", xff)
	// A second hop is a second warning: an operator needs both addresses.
	send("172.18.0.10:1", map[string]string{"X-Real-IP": "203.0.113.7"})
	// A trusted hop is the configuration working; nothing to report.
	send("127.0.0.1:1", xff)
	// No forwarded header at all is an ordinary direct client.
	send("172.18.0.11:1", nil)

	if got := counterValue(t, forwardedFromUntrustedHopTotal) - before; got != 4 {
		t.Errorf("counter moved by %v, want 4 (three from the first hop, one from the second)", got)
	}

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("want one warning per distinct hop (2), got %d: %v", len(entries), entries)
	}

	var hops []string
	for _, e := range entries {
		if !strings.Contains(e.Message, "not a trusted proxy") {
			t.Errorf("warning does not say what happened: %q", e.Message)
		}
		for _, f := range e.Context {
			if f.Key == "hop" {
				hops = append(hops, f.String)
			}
		}
		var hasFix bool
		for _, f := range e.Context {
			if f.Key == "fix" && strings.Contains(f.String, "OIDX_TRUSTED_PROXIES") {
				hasFix = true
			}
		}
		if !hasFix {
			// A warning an operator cannot act on is a warning they turn off.
			t.Errorf("warning does not name the variable to set: %v", e.Context)
		}
	}
	sort.Strings(hops)
	if want := []string{"172.18.0.9", "172.18.0.10"}; !equalUnordered(hops, want) {
		t.Errorf("warnings named hops %v, want %v", hops, want)
	}
}

// A client can send X-Forwarded-For on every request. The report must not let
// that grow anything without bound.
func TestUntrustedHopReportingIsBounded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("OIDX_TRUSTED_PROXIES", "")

	core, logs := observer.New(zap.WarnLevel)
	r := gin.New()
	ConfigureTrustedProxies(r, zap.New(core))
	r.GET("/ip", func(c *gin.Context) { c.Status(http.StatusOK) })

	before := counterValue(t, forwardedFromUntrustedHopTotal)

	const hops = maxReportedHops * 3
	for i := 0; i < hops; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1", i%256)
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Every request is still counted — the metric is what tells an operator the
	// rate. Only the remembered set is capped.
	if got := counterValue(t, forwardedFromUntrustedHopTotal) - before; got != hops {
		t.Errorf("counter moved by %v, want %d — the metric must not be suppressed with the log", got, hops)
	}
	if n := len(logs.All()); n > maxReportedHops {
		t.Errorf("logged %d warnings for %d hops; the remembered set is capped at %d", n, hops, maxReportedHops)
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Eight of eight service mains call ConfigureTrustedProxies today. A complete
// set is exactly when a guard is cheap and exactly when nobody writes one — the
// security-header omission was seven out of eight and invisible for that reason.
// The detector above is mounted from inside ConfigureTrustedProxies, so this one
// assertion covers both: a main that skips the call gets gin's trust-everything
// default AND no report saying so.
func TestEveryHTTPServiceConfiguresTrustedProxies(t *testing.T) {
	root := securityRepoRoot(t)
	cmdDir := filepath.Join(root, "cmd")

	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}

	var httpServices, missing []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		calls, err := serviceMainCalls(filepath.Join(cmdDir, e.Name()))
		if err != nil {
			t.Fatalf("inspect %s: %v", e.Name(), err)
		}
		if !calls["gin.New"] && !calls["gin.Default"] {
			continue // a CLI tool, not an HTTP service
		}
		httpServices = append(httpServices, e.Name())
		if !calls["ConfigureTrustedProxies"] {
			missing = append(missing, e.Name())
		}
	}
	sort.Strings(httpServices)
	sort.Strings(missing)

	if len(httpServices) < 5 {
		t.Fatalf("found only %d gin-based service mains (%v) — the detector is not seeing cmd/",
			len(httpServices), httpServices)
	}
	if len(missing) != 0 {
		t.Errorf("HTTP service(s) that build a gin engine but never call ConfigureTrustedProxies: %s\n\n"+
			"gin's default trusts every proxy, so c.ClientIP() becomes whatever the caller puts in "+
			"X-Forwarded-For — spoofable known-IP device trust, geo rules, risk scores, rate-limit keys "+
			"and audit records. Add middleware.ConfigureTrustedProxies(router, log) before the first "+
			"router.Use.\nHTTP services found: %s",
			strings.Join(missing, ", "), strings.Join(httpServices, ", "))
	}
}

// serviceMainCalls returns the set of functions dir's Go files CALL, as
// "pkg.Name" for a package-qualified call and "Name" for the bare selector, so a
// caller can ask about a function whose import alias differs between mains.
// Matching on the call and not on the file text keeps a mention in a comment
// from counting as a mount.
func serviceMainCalls(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	calls := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			calls[sel.Sel.Name] = true
			if pkg, ok := sel.X.(*ast.Ident); ok {
				calls[pkg.Name+"."+sel.Sel.Name] = true
			}
			return true
		})
	}
	return calls, nil
}
