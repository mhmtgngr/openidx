package oauth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openidx/openidx/internal/common/netutil"
)

// AN SSF STREAM'S DELIVERY ENDPOINT IS AN ORGANIZATION ADMINISTRATOR'S URL,
// and every security event for the stream is pushed to it from inside the
// platform's network with the stream's bearer token. The push goes through
// the outbound guard: an endpoint on the platform's own network -- one saved
// before stream management checked it, or a name that has moved inward since
// -- is not reached, and the item is retried and dead-lettered as any failed
// push is. A public receiver still gets its events.
func TestAnSSFPushReachesPublicReceiversOnly(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, ssfDeliverySchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db

	var internalHits, receiverHits atomic.Int64
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer internal.Close()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receiverHits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()
	_, internalPort, _ := net.SplitHostPort(internal.Listener.Addr().String())

	// rp.example.test is a public receiver, routed to the local one;
	// moved.example.test resolved publicly when its stream was saved and
	// resolves to loopback now.
	var d net.Dialer
	guard := netutil.NewOutboundGuard(netutil.Allowlist{}).WithProxy(nil).
		WithResolver(netutil.ResolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
			switch host {
			case "rp.example.test":
				return []netip.Addr{netip.MustParseAddr("203.0.113.50")}, nil
			case "moved.example.test":
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		})).
		WithDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "203.0.113.50:80" {
				address = receiver.Listener.Addr().String()
			}
			return d.DialContext(ctx, network, address)
		})
	prev := orgOutboundGuard
	orgOutboundGuard = func() *netutil.OutboundGuard { return guard }
	t.Cleanup(func() { orgOutboundGuard = prev })

	item := func(endpoint string) int64 {
		t.Helper()
		var streamID string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
			VALUES ('00000000-0000-0000-0000-0000000000aa', 'https://rp.example', $1)
			RETURNING id::text`, endpoint).Scan(&streamID); err != nil {
			t.Fatalf("seed stream: %v", err)
		}
		var id int64
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO ssf_stream_delivery (stream_id, event_type, set_jwt)
			VALUES ($1, 'session-revoked', 'jwt') RETURNING id`, streamID).Scan(&id); err != nil {
			t.Fatalf("seed delivery: %v", err)
		}
		return id
	}
	direct := item(internal.URL + "/events")
	moved := item("http://moved.example.test:" + internalPort + "/events")
	public := item("http://rp.example.test/events")

	if n, err := svc.drainSSFDelivery(ctx); err != nil || n != 3 {
		t.Fatalf("drain = %d, %v; want 3 items pushed", n, err)
	}

	state := func(id int64) (string, string) {
		t.Helper()
		var st, lastErr string
		if err := db.Pool.QueryRow(ctx,
			`SELECT state, COALESCE(last_error, '') FROM ssf_stream_delivery WHERE id = $1`, id).Scan(&st, &lastErr); err != nil {
			t.Fatalf("read delivery %d: %v", id, err)
		}
		return st, lastErr
	}
	for _, c := range []struct {
		id   int64
		want string
	}{{direct, "127.0.0.1 is a loopback address"}, {moved, "moved.example.test resolves to a loopback address"}} {
		st, lastErr := state(c.id)
		if st != "pending" || !strings.Contains(lastErr, c.want) {
			t.Errorf("delivery %d is %q with %q; want it rescheduled with the refusal (%s)", c.id, st, lastErr, c.want)
		}
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("the internal server was reached %d times", n)
	}
	if st, lastErr := state(public); st != "delivered" || receiverHits.Load() != 1 {
		t.Errorf("the public receiver's delivery is %q (%s) after %d requests; want delivered once", st, lastErr, receiverHits.Load())
	}
}
