package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// The proxy judges the resource's conditions with the request's own
// situation, through the real handler: a route, its application, an assigned
// person whose device the proxy has never seen, and an upstream that counts
// what reaches it. The resource's require_device_trust refuses that person
// under enforcement and names why; when the resource relaxes it, the route's
// pre-228 copy of the same condition does not overrule the resource; and
// where the resource declared no conditions, or the decision is not
// enforced, the route's copy rules as it always did.
func TestProxyJudgesTheResourcesConditions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	host := "ledger-" + suffix + ".example.test"

	var routeID, appID, userID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
		org, "ledger-"+suffix, "https://"+host, upstream.URL).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO applications (org_id, client_id, name, type, route_id)
		VALUES ($1::uuid, $2, 'Ledger', 'web', $3::uuid) RETURNING id::text`,
		org, "ledger-"+suffix, routeID).Scan(&appID); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "clerk-"+suffix, "clerk-"+suffix+"@example.test").Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO user_application_assignments (user_id, application_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, userID, appID, org); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	token := "cookie-" + suffix
	blob, _ := json.Marshal(map[string]interface{}{
		"id": "sess-" + suffix, "user_id": userID, "email": "clerk@example.test", "name": "Clerk",
		"roles": []string{}, "host": host,
		"expires": time.Now().Add(time.Hour).Unix(), "last_active": time.Now().Unix(),
	})
	if err := rc.Set(ctx, "proxy_session:"+hashToken(token), blob, time.Hour).Err(); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// A fresh Service per request: decisions are cached on the Service.
	request := func(enforce bool) (*http.Response, string) {
		t.Helper()
		logger := zap.NewNop()
		svc := &Service{
			db:           db,
			redis:        &database.RedisClient{Client: rc},
			config:       &config.Config{AccessAssignmentEnforce: enforce},
			logger:       logger,
			auditService: NewUnifiedAuditService(db, logger),
		}
		router := gin.New()
		router.NoRoute(svc.handleProxy)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/entries", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: token})
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(body)
	}
	exec := func(sql string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	refused := func(t *testing.T, resp *http.Response, body, why string) {
		t.Helper()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, why) {
			t.Fatalf("got %d %q, want 403 naming %q", resp.StatusCode, body, why)
		}
	}
	reached := func(t *testing.T, resp *http.Response, body string, before int32) {
		t.Helper()
		if resp.StatusCode != http.StatusOK || body != "upstream-ok" || upstreamHits.Load() != before+1 {
			t.Fatalf("got %d %q (upstream hits %d → %d), want the upstream's 200", resp.StatusCode, body, before, upstreamHits.Load())
		}
	}

	t.Run("the resource's device-trust condition refuses an unknown device and says so", func(t *testing.T) {
		exec(`INSERT INTO resource_conditions (application_id, org_id, require_device_trust) VALUES ($1::uuid, $2::uuid, true)`, appID, org)
		before := upstreamHits.Load()
		resp, body := request(true)
		refused(t, resp, body, "device_trust_required")
		if resp.Header.Get("X-Step-Up-Required") != "true" {
			t.Error("a trusted device would change the answer; the step-up header must say so")
		}
		if upstreamHits.Load() != before {
			t.Fatal("the upstream was reached")
		}
		// The durable decision record, the same shape the assignment gate
		// writes: a refused condition is a refused decision.
		var recorded int
		if err := db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM unified_audit_events
			 WHERE event_type = $1 AND user_id = $2::uuid AND source = $3`,
			appaccess.DecisionEventType(true), userID, appaccess.SourceProxy).Scan(&recorded); err != nil || recorded != 1 {
			t.Fatalf("the refusal is recorded as an enforced decision: %d %v", recorded, err)
		}
	})

	t.Run("the resource rules over the route's pre-228 copy", func(t *testing.T) {
		exec(`UPDATE resource_conditions SET require_device_trust = false WHERE application_id = $1::uuid`, appID)
		exec(`UPDATE proxy_routes SET require_device_trust = true WHERE id = $1::uuid`, routeID)
		before := upstreamHits.Load()
		resp, body := request(true)
		reached(t, resp, body, before)
	})

	t.Run("in observe mode the route's copy still rules", func(t *testing.T) {
		resp, body := request(false)
		refused(t, resp, body, "device is not trusted")
	})

	t.Run("a resource that declared no conditions leaves the route's copy in charge", func(t *testing.T) {
		exec(`DELETE FROM resource_conditions WHERE application_id = $1::uuid`, appID)
		resp, body := request(true)
		refused(t, resp, body, "device is not trusted")
		exec(`UPDATE proxy_routes SET require_device_trust = false WHERE id = $1::uuid`, routeID)
		before := upstreamHits.Load()
		resp, body = request(true)
		reached(t, resp, body, before)
	})
}
