package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/netutil"
)

// testWebhookGuard is the outbound guard for tests whose receiver is a local
// server: loopback is allowlisted, as an operator's OIDX_OUTBOUND_ALLOWLIST
// would allow it, every name resolves to a public test address without DNS,
// and nothing goes through a proxy.
func testWebhookGuard(tb testing.TB) *netutil.OutboundGuard {
	tb.Helper()
	allow, err := netutil.ParseAllowlist("127.0.0.0/8")
	if err != nil {
		tb.Fatal(err)
	}
	return netutil.NewOutboundGuard(allow).WithProxy(nil).WithResolver(
		netutil.ResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		}))
}

// streamNet is DNS and the network for the audit stream's webhook tests:
// names answer from a table (in turn, the last answer repeating), made-up
// public addresses are routed to local servers, and a name handed to the
// dialer is resolved through the same table, as a system dialer would.
type streamNet struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups map[string]int
	routes  map[string]string
}

func (n *streamNet) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	seq, ok := n.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := n.lookups[host]
	n.lookups[host]++
	if i >= len(seq) {
		i = len(seq) - 1
	}
	return []netip.Addr{netip.MustParseAddr(seq[i])}, nil
}

func (n *streamNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, perr := netip.ParseAddr(host); perr != nil {
		addrs, lerr := n.LookupNetIP(ctx, "ip", host)
		if lerr != nil {
			return nil, lerr
		}
		address = net.JoinHostPort(addrs[0].String(), port)
	}
	n.mu.Lock()
	if to, ok := n.routes[address]; ok {
		address = to
	}
	n.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (n *streamNet) guard() *netutil.OutboundGuard {
	return netutil.NewOutboundGuard(netutil.Allowlist{}).WithProxy(nil).WithResolver(n).WithDialer(n.dial)
}

type hitServer struct {
	hits atomic.Int64
	srv  *httptest.Server
}

func newHitServer(t *testing.T, h http.HandlerFunc) *hitServer {
	t.Helper()
	s := &hitServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *hitServer) port() string {
	_, p, _ := net.SplitHostPort(s.srv.Listener.Addr().String())
	return p
}

// AN AUDIT-STREAM WEBHOOK IS POSTED FROM INSIDE THE PLATFORM to the URL its
// registrant typed in, with every audit event that matches its filters. A URL
// on the platform's own network is refused when it is registered, with what
// is wrong said plainly.
func TestAnAuditWebhookToAnInternalAddressIsRefusedWhenRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	n := &streamNet{answers: map[string][]string{
		"hooks.example.test":    {"203.0.113.10"},
		"metadata.example.test": {"169.254.169.254"},
	}, lookups: map[string]int{}}
	streamer := NewEventStreamer(zap.NewNop(), createTestService(t), []string{"https://example.com"})
	streamer.guard = n.guard()
	router := gin.New()
	streamer.RegisterRoutes(router.Group("/api/v1/audit"))

	register := func(url string) (int, map[string]interface{}) {
		body, _ := json.Marshal(map[string]interface{}{"url": url, "secret": "test-secret", "enabled": true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/webhooks", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1:8443/hook",
		"https://[::ffff:10.0.0.1]/hook",
		"http://0.0.0.0:8004/api/v1/audit/events",
		"https://metadata.example.test/hook",
	} {
		code, body := register(u)
		if code != http.StatusBadRequest {
			t.Errorf("registering %s answered %d %v, want 400", u, code, body)
			continue
		}
		if msg, _ := body["error"].(string); !strings.HasPrefix(msg, "webhook URL is not allowed: ") || strings.Contains(msg, "169.254.169.254") && strings.Contains(u, "metadata.example.test") {
			t.Errorf("registering %s: error %q", u, msg)
		}
		if hint, _ := body["hint"].(string); !strings.Contains(hint, netutil.OutboundAllowlistEnv) {
			t.Errorf("registering %s: hint %q does not name the allowlist", u, hint)
		}
	}
	if code, body := register("https://hooks.example.test/hook"); code != http.StatusCreated {
		t.Errorf("a public webhook answered %d %v, want 201", code, body)
	}
}

// Delivery is held to the same rule at the connection: a name that moved to
// an internal address since it was registered is refused, a redirect is not
// followed, and a public receiver still gets its events.
func TestAnAuditWebhookDeliveryReachesPublicReceiversOnly(t *testing.T) {
	internal := newHitServer(t, nil)
	receiver := newHitServer(t, nil)
	redirector := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:"+internal.port()+"/latest/meta-data/", http.StatusFound)
	})
	n := &streamNet{
		answers: map[string][]string{
			"rebind.example.test":   {"203.0.113.10", "127.0.0.1"},
			"hooks.example.test":    {"203.0.113.20"},
			"redirect.example.test": {"203.0.113.30"},
		},
		lookups: map[string]int{},
		routes: map[string]string{
			"203.0.113.20:80": receiver.srv.Listener.Addr().String(),
			"203.0.113.30:80": redirector.srv.Listener.Addr().String(),
		},
	}
	streamer := NewEventStreamer(zap.NewNop(), createTestService(t), []string{"https://example.com"})
	streamer.guard = n.guard()
	streamer.webhookConfig.Timeout = 5 * time.Second
	deliver := func(url string) bool {
		return streamer.deliverWebhook(&WebhookDelivery{
			Event:      &ServiceAuditEvent{ID: "event-1", Timestamp: time.Now().UTC(), EventType: EventTypeAuthentication},
			WebhookURL: url,
			ID:         "delivery-1",
		})
	}

	rebind := "http://rebind.example.test:" + internal.port() + "/hook"
	if err := streamer.guard.CheckURL(context.Background(), rebind); err != nil {
		t.Fatalf("at registration the name is public: %v", err)
	}
	if deliver(rebind) {
		t.Error("a delivery to a name that now resolves to loopback succeeded")
	}
	if deliver("http://redirect.example.test/hook") {
		t.Error("a redirect was counted as a delivery")
	}
	if got := internal.hits.Load(); got != 0 {
		t.Errorf("the internal server was reached %d times", got)
	}
	if redirector.hits.Load() != 1 {
		t.Errorf("the redirecting receiver was reached %d times, want once", redirector.hits.Load())
	}

	if !deliver("http://hooks.example.test/hook") || receiver.hits.Load() != 1 {
		t.Errorf("a public receiver did not get its event (hits=%d)", receiver.hits.Load())
	}
}
