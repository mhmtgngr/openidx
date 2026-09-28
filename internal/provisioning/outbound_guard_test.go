package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/netutil"
)

// testOutbound is the outbound guard for the outbound-SCIM tests. Their fake
// service providers are local servers, so loopback is allowlisted, as an
// operator's OIDX_OUTBOUND_ALLOWLIST would allow it. Every name resolves to
// 203.0.113.10, a documentation address, and a connection to that network is
// refused at once: a target like https://x/scim fails as fast as the name
// that did not resolve used to, instead of waiting out a dial timeout.
func testOutbound(tb testing.TB) *netutil.OutboundGuard {
	tb.Helper()
	allow, err := netutil.ParseAllowlist("127.0.0.0/8")
	if err != nil {
		tb.Fatal(err)
	}
	testNet := netip.MustParsePrefix("203.0.113.0/24")
	var d net.Dialer
	return netutil.NewOutboundGuard(allow).WithProxy(nil).
		WithResolver(netutil.ResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		})).
		WithDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			if ap, err := netip.ParseAddrPort(address); err == nil && testNet.Contains(ap.Addr()) {
				return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
			}
			return d.DialContext(ctx, network, address)
		})
}

// AN OUTBOUND SCIM TARGET IS A URL AN ORGANIZATION'S ADMINISTRATOR TYPES IN,
// and the worker sends the organization's users to it from inside the
// platform's network with the target's bearer token; the connection test
// shows a failed call's answer back. A base URL on the platform's own network
// is refused when it is saved, and a target saved before that check is not
// reached by the connection test or the worker. A public target still is.
func TestAnOutboundSCIMTargetOnThePlatformsOwnNetworkIsRefused(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	var internalHits atomic.Int64
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		http.Error(w, `{"SecretAccessKey":"internal-secret"}`, http.StatusBadRequest)
	}))
	defer internal.Close()

	sp := newFakeSP()
	spSrv := sp.server()
	defer spSrv.Close()

	// scim.example.test is a public service provider: its address is routed
	// to the fake SP. metadata.example.test is a name that resolves inward.
	var d net.Dialer
	guard := netutil.NewOutboundGuard(netutil.Allowlist{}).WithProxy(nil).
		WithResolver(netutil.ResolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
			switch host {
			case "scim.example.test":
				return []netip.Addr{netip.MustParseAddr("203.0.113.40")}, nil
			case "metadata.example.test":
				return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		})).
		WithDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "203.0.113.40:80" {
				address = spSrv.Listener.Addr().String()
			}
			return d.DialContext(ctx, network, address)
		})
	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}, outbound: guard}
	r := newOutboundTestRouter(svc)

	targets := func() int {
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM scim_target_apps`).Scan(&n); err != nil {
			t.Fatalf("count targets: %v", err)
		}
		return n
	}

	for _, u := range []string{
		internal.URL + "/scim/v2",
		"https://169.254.169.254/latest/meta-data/",
		"https://[::ffff:10.0.0.1]/scim/v2",
		"https://metadata.example.test/scim/v2",
	} {
		w := doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{
			Name: "internal", BaseURL: u, AuthType: "bearer", BearerToken: "tok", ProvisionUsers: true, Enabled: true,
		})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "base_url is not allowed") {
			t.Errorf("creating a target at %s answered %d %s, want 400 base_url is not allowed", u, w.Code, w.Body)
		}
		if strings.Contains(u, "metadata.example.test") && strings.Contains(w.Body.String(), "169.254") {
			t.Errorf("the refusal tells the administrator where an internal name resolves: %s", w.Body)
		}
	}
	if n := targets(); n != 0 {
		t.Fatalf("%d refused targets were stored", n)
	}

	// A public target is taken, and a change of its base URL is held to the
	// same rule.
	w := doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{
		Name: "public", BaseURL: "http://scim.example.test", AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("creating a public target answered %d %s", w.Code, w.Body)
	}
	var public TargetApp
	if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil {
		t.Fatalf("decode target: %v", err)
	}
	if _, err := svc.UpdateTargetApp(ctx, testOrgID, public.ID, &TargetAppInput{BaseURL: "http://127.0.0.1:8003/scim/v2", Enabled: true}); !errors.Is(err, netutil.ErrDestinationNotAllowed) {
		t.Errorf("moving a target to loopback = %v, want a refused destination", err)
	}
	back, err := svc.GetTargetApp(ctx, testOrgID, public.ID)
	if err != nil || back.BaseURL != "http://scim.example.test" {
		t.Fatalf("after a refused update the target is %+v, %v", back, err)
	}

	// A target saved before the check, pointing at an internal server.
	var legacy string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO scim_target_apps (org_id, name, base_url, auth_type, provision_users, enabled)
		VALUES ($1, 'legacy', $2, 'bearer', true, true) RETURNING id::text`,
		testOrgID, internal.URL+"/scim/v2").Scan(&legacy); err != nil {
		t.Fatalf("seed the legacy target: %v", err)
	}
	w = doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets/"+legacy+"/test", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":false`) ||
		!strings.Contains(w.Body.String(), "loopback") || strings.Contains(w.Body.String(), "internal-secret") {
		t.Errorf("the connection test of the legacy target answered %d %s; want ok:false with the refusal, never the internal answer", w.Code, w.Body)
	}

	// The worker: one user, queued for both targets. The public one gets it;
	// the legacy one fails without reaching the internal server.
	userID := "22222222-2222-2222-2222-222222222222"
	snap := userSnapshot{ID: userID, UserName: "bob@corp.example", Email: "bob@corp.example", Active: true}
	if n, err := svc.EnqueueUserOp(ctx, testOrgID, userID, OpCreate, snap); err != nil || n != 2 {
		t.Fatalf("EnqueueUserOp = %d, %v; want one item per enabled target", n, err)
	}
	worker := &outboundWorker{svc: svc, cfg: OutboundWorkerConfig{BatchSize: 10}, logger: zap.NewNop()}
	if _, err := worker.drainBatch(ctx); err != nil {
		t.Fatalf("drainBatch: %v", err)
	}
	if sp.created != 1 {
		t.Errorf("the public target received %d creates, want 1", sp.created)
	}
	var lastErr string
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(last_error, '') FROM scim_provisioning_queue WHERE target_id = $1::uuid`, legacy).Scan(&lastErr); err != nil {
		t.Fatalf("read the legacy target's queue item: %v", err)
	}
	if !strings.Contains(lastErr, "loopback") {
		t.Errorf("the legacy target's item failed with %q, want the refusal", lastErr)
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("the internal server was reached %d times", n)
	}
}
