package webhooks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/netutil"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// A WEBHOOK IS A REQUEST FROM INSIDE THE PLATFORM TO A URL AN ORGANIZATION'S
// ADMINISTRATOR TYPED IN, and the first thousand bytes of the answer are kept
// in webhook_deliveries.response_body, where that administrator reads them.
// Pointed at 169.254.169.254 or at another service's port, it was a way to
// read the platform's own network.
//
// Each test below runs the real service against real tables. DNS is a table
// the test controls, and "the internet" is a dialer that delivers a
// connection for a made-up public address to a local server -- and resolves a
// name it is handed through the same table, as a system dialer would, so a
// guard that skipped its check would connect to the internal server and the
// test would see it.

// fakeNet is the DNS and the network these tests run on.
type fakeNet struct {
	mu      sync.Mutex
	answers map[string][]string // successive answers per name; the last repeats
	lookups map[string]int
	routes  map[string]string // public "ip:port" -> a local server's address
	dialed  []string
}

func newFakeNet(answers map[string][]string) *fakeNet {
	return &fakeNet{answers: answers, lookups: map[string]int{}, routes: map[string]string{}}
}

func (n *fakeNet) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
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
	var out []netip.Addr
	for _, a := range strings.Split(seq[i], ",") {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func (n *fakeNet) route(publicAddr string, srv *httptest.Server) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[publicAddr] = srv.Listener.Addr().String()
}

func (n *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
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
	n.dialed = append(n.dialed, address)
	if to, ok := n.routes[address]; ok {
		address = to
	}
	n.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (n *fakeNet) dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

// server is a local HTTP server that counts what reaches it.
type server struct {
	hits atomic.Int64
	srv  *httptest.Server
	last atomic.Pointer[http.Header]
}

func newServer(t *testing.T, h http.HandlerFunc) *server {
	t.Helper()
	s := &server{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		hdr := r.Header.Clone()
		s.last.Store(&hdr)
		if h != nil {
			h(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"AccessKeyId":"ASIA-INTERNAL","SecretAccessKey":"internal-secret"}`)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *server) port() string {
	_, p, _ := net.SplitHostPort(s.srv.Listener.Addr().String())
	return p
}

// guardedService is the webhook service with the tables, an organization,
// and an outbound guard on the fake network with the given allowlist.
func guardedService(t *testing.T, allow string, fn *fakeNet) (*Service, *pgxpool.Pool, context.Context) {
	t.Helper()
	pool := openWebhookPool(t)
	createWebhookTables(t, pool)
	a, err := netutil.ParseAllowlist(allow)
	require.NoError(t, err)
	svc := NewService(&database.PostgresDB{Pool: database.NewScopedPool(pool)}, nil, zap.NewNop(), secretcrypt.NewNoop())
	svc.SetOutboundGuard(netutil.NewOutboundGuard(a).WithProxy(nil).WithResolver(fn).WithDialer(fn.dial))
	return svc, pool, orgctx.With(context.Background(), orgctx.Org{ID: uuid.NewString()})
}

// pendingDelivery queues one event for a subscription, as Publish would.
func pendingDelivery(t *testing.T, pool *pgxpool.Pool, subID string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, org_id)
		SELECT $1, id, 'user.created', '{"user_id":"u1"}', 0, 'pending', org_id FROM webhook_subscriptions WHERE id = $2`,
		id, subID)
	require.NoError(t, err)
	return id
}

type deliveryRow struct {
	status         string
	responseStatus *int
	responseBody   *string
}

func readDelivery(t *testing.T, pool *pgxpool.Pool, id string) deliveryRow {
	t.Helper()
	var d deliveryRow
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT status, response_status, response_body FROM webhook_deliveries WHERE id = $1`, id).
		Scan(&d.status, &d.responseStatus, &d.responseBody))
	return d
}

func subscriptionCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM webhook_subscriptions`).Scan(&n))
	return n
}

func TestAWebhookToAnInternalAddressIsRefusedWhenItIsCreated(t *testing.T) {
	fn := newFakeNet(map[string][]string{
		"hooks.example.test":    {"203.0.113.10"},
		"metadata.example.test": {"169.254.169.254"},
	})
	svc, pool, ctx := guardedService(t, "", fn)

	for _, u := range []string{
		"https://127.0.0.1:8443/hook",
		"https://[::ffff:7f00:1]/hook",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"https://10.0.0.5/hook",
		"https://metadata.example.test/hook",
	} {
		sub, err := svc.CreateSubscription(ctx, "hook", u, "signing-secret-0123", []string{EventUserCreated}, "")
		var refused *netutil.DestinationError
		if !errors.As(err, &refused) {
			t.Errorf("CreateSubscription(%s) = %v, %v; want a refused destination", u, sub, err)
		}
	}
	require.Equal(t, 0, subscriptionCount(t, pool), "a refused URL was stored")

	// The same service takes a public destination, and holds a change of URL
	// to the same rule.
	sub, err := svc.CreateSubscription(ctx, "hook", "https://hooks.example.test/hook", "signing-secret-0123", []string{EventUserCreated}, "")
	require.NoError(t, err, "a public destination must still be accepted")
	require.Equal(t, 1, subscriptionCount(t, pool))

	err = svc.UpdateSubscription(ctx, sub.ID, "hook", "https://127.0.0.1/hook", []string{EventUserCreated}, "active")
	require.ErrorIs(t, err, netutil.ErrDestinationNotAllowed)
	var stored string
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT url FROM webhook_subscriptions WHERE id = $1`, sub.ID).Scan(&stored))
	require.Equal(t, "https://hooks.example.test/hook", stored, "a refused update changed the URL")
}

// THE REBINDING NAME: public when the subscription is created and when the
// delivery is checked, the platform's loopback by the time the connection is
// opened. The internal server must not see the request, and what the
// administrator reads back must not be its answer.
func TestAWebhookWhoseNameMovesToAnInternalAddressIsRefusedAtTheConnection(t *testing.T) {
	internal := newServer(t, nil)
	fn := newFakeNet(map[string][]string{
		"rebind.example.test": {"203.0.113.10", "203.0.113.10", "127.0.0.1"},
	})
	svc, pool, ctx := guardedService(t, "", fn)

	sub, err := svc.CreateSubscription(ctx, "hook", "http://rebind.example.test:"+internal.port()+"/hook",
		"signing-secret-0123", []string{EventUserCreated}, "")
	require.NoError(t, err, "at creation the name is public")
	id := pendingDelivery(t, pool, sub.ID)

	err = svc.deliverWebhook(bypassCtx(), id)
	require.ErrorIs(t, err, netutil.ErrDestinationNotAllowed)

	require.Zero(t, internal.hits.Load(), "the internal server was reached through a name that moved to loopback")
	require.Empty(t, fn.dials(), "a refused name was dialed")
	d := readDelivery(t, pool, id)
	require.Equal(t, "pending", d.status, "the refusal is a failed attempt, retried on the usual schedule")
	require.Nil(t, d.responseStatus)
	require.NotNil(t, d.responseBody)
	require.Contains(t, *d.responseBody, "rebind.example.test resolves to a loopback address")
	require.NotContains(t, *d.responseBody, "127.0.0.1", "the stored error discloses where the name resolved")
	require.NotContains(t, *d.responseBody, "internal-secret")
}

// A receiver's redirect is its answer. Following it would let whoever answers
// pick the next destination -- the cloud metadata endpoint included.
func TestAWebhookRedirectIsRecordedAndNotFollowed(t *testing.T) {
	internal := newServer(t, nil)
	elsewhere := newServer(t, nil)
	for _, target := range []string{
		"http://127.0.0.1:" + internal.port() + "/latest/meta-data/",
		"http://elsewhere.example.test/",
	} {
		t.Run(target, func(t *testing.T) {
			fn := newFakeNet(map[string][]string{
				"hooks.example.test":     {"203.0.113.10"},
				"elsewhere.example.test": {"203.0.113.20"},
			})
			redirector := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			})
			fn.route("203.0.113.10:80", redirector.srv)
			fn.route("203.0.113.20:80", elsewhere.srv)
			svc, pool, ctx := guardedService(t, "", fn)

			sub, err := svc.CreateSubscription(ctx, "hook", "http://hooks.example.test/hook", "signing-secret-0123", []string{EventUserCreated}, "")
			require.NoError(t, err)
			id := pendingDelivery(t, pool, sub.ID)
			require.NoError(t, svc.deliverWebhook(bypassCtx(), id))

			require.Equal(t, int64(1), redirector.hits.Load())
			require.Zero(t, internal.hits.Load(), "the redirect to the metadata endpoint was followed")
			require.Zero(t, elsewhere.hits.Load(), "the redirect to an unchecked host was followed")
			d := readDelivery(t, pool, id)
			require.Equal(t, "pending", d.status, "a 3xx is not a delivery")
			require.NotNil(t, d.responseStatus)
			require.Equal(t, http.StatusTemporaryRedirect, *d.responseStatus)
		})
	}
}

func TestAWebhookToAPublicAddressIsStillDelivered(t *testing.T) {
	receiver := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "thanks") })
	fn := newFakeNet(map[string][]string{"hooks.example.test": {"203.0.113.10"}})
	fn.route("203.0.113.10:80", receiver.srv)
	svc, pool, ctx := guardedService(t, "", fn)

	sub, err := svc.CreateSubscription(ctx, "hook", "http://hooks.example.test/hook", "signing-secret-0123", []string{EventUserCreated}, "")
	require.NoError(t, err)
	id := pendingDelivery(t, pool, sub.ID)
	require.NoError(t, svc.deliverWebhook(bypassCtx(), id))

	require.Equal(t, int64(1), receiver.hits.Load())
	hdr := receiver.last.Load()
	require.NotNil(t, hdr)
	require.NotEmpty(t, hdr.Get("X-Webhook-Signature"), "the delivery is signed as before")
	require.Equal(t, []string{"203.0.113.10:80"}, fn.dials(), "the connection goes to the address that was checked")
	d := readDelivery(t, pool, id)
	require.Equal(t, "delivered", d.status)
	require.Equal(t, http.StatusOK, *d.responseStatus)
	require.Equal(t, "thanks", *d.responseBody)
}

// OIDX_OUTBOUND_ALLOWLIST is the operator's way to let webhooks reach a
// receiver on their own network, by CIDR or by name.
func TestAnAllowlistedInternalWebhookIsDelivered(t *testing.T) {
	for _, tc := range []struct{ allow, host string }{
		{"127.0.0.0/8", "127.0.0.1"},
		{"hooks.corp.example", "hooks.corp.example"},
	} {
		t.Run(tc.allow, func(t *testing.T) {
			receiver := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
			fn := newFakeNet(map[string][]string{"hooks.corp.example": {"127.0.0.1"}})
			svc, pool, ctx := guardedService(t, tc.allow, fn)

			sub, err := svc.CreateSubscription(ctx, "hook", "http://"+tc.host+":"+receiver.port()+"/hook",
				"signing-secret-0123", []string{EventUserCreated}, "")
			require.NoError(t, err, "an allowlisted destination was refused at creation")
			id := pendingDelivery(t, pool, sub.ID)
			require.NoError(t, svc.deliverWebhook(bypassCtx(), id))

			require.Equal(t, int64(1), receiver.hits.Load())
			require.Equal(t, "delivered", readDelivery(t, pool, id).status)
		})
	}
}

// A subscription saved before the guard existed is not grandfathered: its
// deliveries and its test ping are refused, and the internal server is not
// reached by either.
func TestASubscriptionToAnInternalAddressSavedEarlierIsRefusedAtDeliveryAndPing(t *testing.T) {
	internal := newServer(t, nil)
	fn := newFakeNet(nil)
	svc, pool, ctx := guardedService(t, "", fn)
	org, err := orgctx.From(ctx)
	require.NoError(t, err)

	subID := uuid.NewString()
	_, err = pool.Exec(context.Background(), `
		INSERT INTO webhook_subscriptions (id, name, url, secret, events, status, org_id)
		VALUES ($1, 'legacy', $2, 'signing-secret-0123', ARRAY['user.created'], 'active', $3)`,
		subID, "http://127.0.0.1:"+internal.port()+"/latest/meta-data/", org.ID)
	require.NoError(t, err)

	id := pendingDelivery(t, pool, subID)
	err = svc.deliverWebhook(bypassCtx(), id)
	require.ErrorIs(t, err, netutil.ErrDestinationNotAllowed)
	d := readDelivery(t, pool, id)
	require.Equal(t, "pending", d.status)
	require.Contains(t, *d.responseBody, "127.0.0.1 is a loopback address")

	ping, err := svc.PingSubscription(ctx, subID)
	require.NoError(t, err, "a ping reports its failure in the delivery it returns")
	require.Equal(t, "failed", ping.Status)
	require.NotNil(t, ping.ResponseBody)
	require.Contains(t, *ping.ResponseBody, "loopback")
	require.NotContains(t, *ping.ResponseBody, "internal-secret")

	require.Zero(t, internal.hits.Load(), "the internal server was reached")
	require.Empty(t, fn.dials())
}

// ONE ORGANIZATION'S REFUSED URL IS NOT EVERY ORGANIZATION'S OUTAGE. The
// delivery client's circuit breaker is shared by every subscription on the
// install and opens after ten failures in a row. A refusal is the
// subscription's own fault, not the receiver's, so it is decided before the
// request and never counted: a dozen deliveries and pings to an internal
// address leave another organization's public receiver reachable.
func TestRefusedDestinationsDoNotOpenTheBreakerEveryOrganizationShares(t *testing.T) {
	internal := newServer(t, nil)
	receiver := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	fn := newFakeNet(map[string][]string{"hooks.example.test": {"203.0.113.10"}})
	fn.route("203.0.113.10:80", receiver.srv)
	svc, pool, ctxA := guardedService(t, "", fn)
	orgA, err := orgctx.From(ctxA)
	require.NoError(t, err)

	legacy := uuid.NewString()
	_, err = pool.Exec(context.Background(), `
		INSERT INTO webhook_subscriptions (id, name, url, secret, events, status, org_id)
		VALUES ($1, 'legacy', $2, 'signing-secret-0123', ARRAY['user.created'], 'active', $3)`,
		legacy, "http://127.0.0.1:"+internal.port()+"/hook", orgA.ID)
	require.NoError(t, err)
	for i := 0; i < 6; i++ {
		require.ErrorIs(t, svc.deliverWebhook(bypassCtx(), pendingDelivery(t, pool, legacy)), netutil.ErrDestinationNotAllowed)
		ping, err := svc.PingSubscription(ctxA, legacy)
		require.NoError(t, err)
		require.Equal(t, "failed", ping.Status)
	}
	require.Zero(t, internal.hits.Load())

	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: uuid.NewString()})
	sub, err := svc.CreateSubscription(ctxB, "hook", "http://hooks.example.test/hook", "signing-secret-0123", []string{EventUserCreated}, "")
	require.NoError(t, err)
	id := pendingDelivery(t, pool, sub.ID)
	require.NoError(t, svc.deliverWebhook(bypassCtx(), id))
	require.Equal(t, "delivered", readDelivery(t, pool, id).status,
		"another organization's delivery failed after one organization's refused URLs: the shared breaker opened")
	require.Equal(t, int64(1), receiver.hits.Load())
}
