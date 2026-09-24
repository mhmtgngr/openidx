package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

// The App assignment row of docs/evidence/display-equals-enforcement.md at the
// access proxy, through the real handler: handleProxy mounted as the router's
// NoRoute, a session cookie, the route resolved from the Host header, and an
// upstream that counts what reaches it.
//
// Until this test, the proxy's half of the row had only
// TestProxyAssignmentDecision, a table over the pure decision function.
// Nothing showed that an unassigned user is refused before the upstream is
// dialled, or that an assigned one still gets through.
//
// The request goes through httptest.NewServer rather than a ResponseRecorder:
// the proxy is an httputil.ReverseProxy, which needs a request context that
// can be cancelled and a writer a recorder does not provide.
func TestProxyEnforcesApplicationAssignment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	var upstreamHits atomic.Int32
	var lastForwardedUser atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		lastForwardedUser.Store(r.Header.Get("X-Forwarded-User"))
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	host := "payroll-" + suffix + ".example.test"

	var routeID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
		org, "payroll-"+suffix, "https://"+host, upstream.URL).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	var appID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO applications (org_id, client_id, name, type, route_id)
		VALUES ($1::uuid, $2, 'Payroll', 'web', $3::uuid) RETURNING id::text`,
		org, "payroll-"+suffix, routeID).Scan(&appID); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	assigned := seedUser("proxy-assigned")
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO user_application_assignments (user_id, application_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, assigned, appID, org); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	session := func(userID string) string {
		t.Helper()
		token := "cookie-" + userID
		blob, err := json.Marshal(map[string]interface{}{
			"id":          "sess-" + userID,
			"user_id":     userID,
			"email":       userID + "@example.test",
			"name":        "Someone",
			"roles":       []string{},
			"expires":     time.Now().Add(time.Hour).Unix(),
			"last_active": time.Now().Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := rc.Set(ctx, "proxy_session:"+hashToken(token), blob, time.Hour).Err(); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		return token
	}

	// A fresh Service per scenario: the assignment answer is cached on the
	// Service, and report mode records only on a fresh lookup.
	request := func(enforce bool, userID string) (*http.Response, string) {
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

		req, err := http.NewRequest(http.MethodGet, srv.URL+"/payslips", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: session(userID)})
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(body)
	}
	// decisions returns the assignment decisions recorded for the user.
	decisions := func(userID string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `
			SELECT event_type || ' ' || COALESCE(route_id::text, '') || ' ' || COALESCE(details->>'application_id', '')
			FROM unified_audit_events
			WHERE user_id = $1::uuid AND source = $2
			ORDER BY created_at`, userID, appaccess.SourceProxy)
		if err != nil {
			t.Fatalf("read decisions: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				t.Fatal(err)
			}
			out = append(out, row)
		}
		return out
	}

	// THE POSITIVE HALF.
	t.Run("under enforcement an assigned user reaches the application", func(t *testing.T) {
		before := upstreamHits.Load()
		resp, body := request(true, assigned)
		if resp.StatusCode != http.StatusOK || body != "upstream-ok" {
			t.Fatalf("got %d %q, want the upstream's 200", resp.StatusCode, body)
		}
		if upstreamHits.Load() != before+1 {
			t.Fatal("the upstream was not reached")
		}
		if got, _ := lastForwardedUser.Load().(string); got != assigned {
			t.Fatalf("the upstream saw X-Forwarded-User %q, want %s", got, assigned)
		}
		if got := decisions(assigned); len(got) != 0 {
			t.Fatalf("recorded %v for an assigned user", got)
		}
	})

	// THE NEGATIVE HALF.
	t.Run("under enforcement an unassigned user is refused before the upstream", func(t *testing.T) {
		unassigned := seedUser("proxy-unassigned")
		before := upstreamHits.Load()
		resp, body := request(true, unassigned)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d %q, want 403", resp.StatusCode, body)
		}
		if upstreamHits.Load() != before {
			t.Fatal("the upstream was reached by an unassigned user")
		}
		want := appaccess.EventTypeDenied + " " + routeID + " " + appID
		if got := decisions(unassigned); len(got) != 1 || got[0] != want {
			t.Fatalf("recorded %v, want exactly [%s]", got, want)
		}
	})

	// Report mode, the state an existing install stays in until it opts in.
	t.Run("in report mode an unassigned user gets through and the gap is recorded", func(t *testing.T) {
		unassigned := seedUser("proxy-report")
		before := upstreamHits.Load()
		resp, body := request(false, unassigned)
		if resp.StatusCode != http.StatusOK || body != "upstream-ok" {
			t.Fatalf("got %d %q, want the upstream's 200", resp.StatusCode, body)
		}
		if upstreamHits.Load() != before+1 {
			t.Fatal("the upstream was not reached")
		}
		want := appaccess.EventTypeWouldDeny + " " + routeID + " " + appID
		if got := decisions(unassigned); len(got) != 1 || got[0] != want {
			t.Fatalf("recorded %v, want exactly [%s]", got, want)
		}
	})
}
