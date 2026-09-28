package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/netutil"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/webhooks"
)

// webhookManager is cmd/admin-api's adapter: the webhook service behind
// the WebhookManager interface, its errors passed through as they are.
type webhookManager struct{ svc *webhooks.Service }

func (a webhookManager) CreateSubscription(ctx context.Context, name, url, secret string, events []string, createdBy string) (interface{}, error) {
	return a.svc.CreateSubscription(ctx, name, url, secret, events, createdBy)
}
func (a webhookManager) ListSubscriptions(ctx context.Context) (interface{}, error) {
	return a.svc.ListSubscriptions(ctx)
}
func (a webhookManager) GetSubscription(ctx context.Context, id string) (interface{}, error) {
	return a.svc.GetSubscription(ctx, id)
}
func (a webhookManager) DeleteSubscription(ctx context.Context, id string) error {
	return a.svc.DeleteSubscription(ctx, id)
}
func (a webhookManager) GetDeliveryHistory(ctx context.Context, subscriptionID string, limit int) (interface{}, error) {
	return a.svc.GetDeliveryHistory(ctx, subscriptionID, limit)
}
func (a webhookManager) RetryDelivery(ctx context.Context, deliveryID string) error {
	return a.svc.RetryDelivery(ctx, deliveryID)
}
func (a webhookManager) Publish(ctx context.Context, eventType string, payload interface{}) error {
	return a.svc.Publish(ctx, eventType, payload)
}
func (a webhookManager) PingSubscription(ctx context.Context, subscriptionID string) (interface{}, error) {
	return a.svc.PingSubscription(ctx, subscriptionID)
}
func (a webhookManager) GetDeliveryStats(ctx context.Context, subscriptionID string) (interface{}, error) {
	return a.svc.GetDeliveryStats(ctx, subscriptionID)
}

// A WEBHOOK URL ON THE PLATFORM'S OWN NETWORK, THROUGH THE REAL ROUTE TABLE.
//
// An organization's administrator creates webhooks, and the platform POSTs to
// them from inside its network and shows the first thousand bytes of each
// answer back. The route used to refuse a handful of host-name prefixes
// ("10.", "192.168.", "localhost"), which [::1], 169.254.169.254, 0.0.0.0,
// an IPv4-mapped address or any name resolving inward walked past. It now
// answers 400 with what is wrong for every one of them and stores nothing,
// takes a public URL as before, and the test ping of a subscription saved
// before the change does not reach the internal address it names.
func TestTheWebhookAPIRefusesADestinationOnThePlatformsOwnNetwork(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	bypass := orgctx.WithBypassRLS(context.Background())

	var org string
	if err := db.Pool.QueryRow(bypass,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		fmt.Sprintf("webhook-destinations-%d", time.Now().UnixNano())).Scan(&org); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	var internalHits atomic.Int64
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = w.Write([]byte(`{"SecretAccessKey":"internal-secret"}`))
	}))
	t.Cleanup(internal.Close)

	whs := webhooks.NewService(db, &database.RedisClient{}, zap.NewNop(), secretcrypt.NewNoop())
	whs.SetOutboundGuard(netutil.NewOutboundGuard(netutil.Allowlist{}).WithProxy(nil).WithResolver(
		netutil.ResolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
			switch host {
			case "hooks.example.test":
				return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
			case "metadata.example.test":
				return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		})))
	svc := NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	svc.SetWebhookService(webhookManager{whs})

	r := gin.New()
	v1 := r.Group("/api/v1")
	admin := uuid.NewString()
	v1.Use(func(c *gin.Context) {
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	RegisterRoutes(v1, svc)

	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	create := func(url string) (int, map[string]interface{}) {
		t.Helper()
		body, _ := json.Marshal(map[string]interface{}{
			"name": "hook", "url": url, "secret": "signing-secret-0123", "events": []string{webhooks.EventUserCreated},
		})
		return call(http.MethodPost, "/api/v1/webhooks", string(body))
	}
	stored := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(bypass, `SELECT count(*) FROM webhook_subscriptions WHERE org_id = $1::uuid`, org).Scan(&n); err != nil {
			t.Fatalf("count subscriptions: %v", err)
		}
		return n
	}

	for _, u := range []string{
		"https://127.0.0.1/hook",
		"https://[::1]:8443/hook",
		"https://0.0.0.0:8005/api/v1/users",
		"https://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"https://[::ffff:a9fe:a9fe]/latest/meta-data/",
		"https://100.100.100.200/latest/meta-data/", // Alibaba Cloud's metadata address, in 100.64.0.0/10
		"https://metadata.example.test/hook",
	} {
		code, body := create(u)
		if code != http.StatusBadRequest {
			t.Errorf("POST /api/v1/webhooks with %s answered %d %v, want 400", u, code, body)
			continue
		}
		msg, _ := body["error"].(string)
		if !strings.HasPrefix(msg, "webhook URL is not allowed: ") {
			t.Errorf("%s: error %q does not say what is wrong", u, msg)
		}
		if hint, _ := body["hint"].(string); !strings.Contains(hint, netutil.OutboundAllowlistEnv) {
			t.Errorf("%s: hint %q does not name the operator's allowlist", u, hint)
		}
		if strings.Contains(u, "metadata.example.test") && strings.Contains(msg, "169.254") {
			t.Errorf("the refusal %q tells the administrator where an internal name resolves", msg)
		}
	}
	if n := stored(); n != 0 {
		t.Fatalf("%d refused webhooks were stored", n)
	}

	if code, body := create("https://hooks.example.test/hook"); code != http.StatusCreated {
		t.Fatalf("a public webhook answered %d %v, want 201", code, body)
	}
	if n := stored(); n != 1 {
		t.Fatalf("%d webhooks stored after the public one, want 1", n)
	}

	// A subscription saved before the check existed, pointing at an internal
	// server. Its test ping fails without reaching it, and the answer shown to
	// the administrator is the refusal, not the server's.
	legacy := uuid.NewString()
	if _, err := db.Pool.Exec(bypass, `
		INSERT INTO webhook_subscriptions (id, org_id, name, url, secret, events, status)
		VALUES ($1, $2::uuid, 'legacy', $3, 'signing-secret-0123', ARRAY['user.created'], 'active')`,
		legacy, org, internal.URL+"/latest/meta-data/"); err != nil {
		t.Fatalf("seed the legacy subscription: %v", err)
	}
	code, body := call(http.MethodPost, "/api/v1/webhooks/"+legacy+"/test", "")
	if code != http.StatusOK {
		t.Fatalf("test ping answered %d %v", code, body)
	}
	delivery, _ := body["delivery"].(map[string]interface{})
	if delivery["status"] != "failed" {
		t.Errorf("the ping to an internal address is %v, want failed", delivery["status"])
	}
	shown, _ := delivery["response_body"].(string)
	if !strings.Contains(shown, "loopback") || strings.Contains(shown, "internal-secret") {
		t.Errorf("the ping shows %q; want the refusal, never the internal server's answer", shown)
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("the internal server was reached %d times", n)
	}
}
