package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/migrations"
)

// The route-based Guacamole connect is the PAM entry launch. The row of
// docs/evidence/display-equals-enforcement.md: for each user, what
// my-connections lists beside what the route's connect does, through the
// real handlers on the migrated schema, against a broker stub.
//
// Before this, POST /guacamole/connections/:routeId/connect asked nothing
// about the caller: an authenticated user of the organization with a route id
// had a session. Each half here has a refused side: the ungranted user, the
// second launch on a single-use approval, the other tenant.
func TestRouteConnectIsTheEntryLaunch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
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
	admin := seedUser("route-admin")
	approver := seedUser("route-approver")
	granted := seedUser("route-granted")
	stranger := seedUser("route-stranger")

	var otherOrg string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "route-b-"+suffix).Scan(&otherOrg); err != nil {
		t.Fatalf("seed the other org: %v", err)
	}

	// A brokered ssh route, as provisioning records it.
	var routeID, connectionPK string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1::uuid, $2, $3, 'ssh://198.51.100.9:22', true) RETURNING id::text`,
		org, "bastion-"+suffix, "https://bastion-"+suffix+".example.test").Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	guacID := "guac-" + suffix
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_connections
		    (route_id, org_id, guacamole_connection_id, protocol, hostname, port, require_approval, record_session)
		VALUES ($1::uuid, $2::uuid, $3, 'ssh', '198.51.100.9', 22, false, false) RETURNING id::text`,
		routeID, org, guacID).Scan(&connectionPK); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	// A broker stub: every call answers 200 with a token, which is what the
	// launch core needs from the connection update and the session token mint.
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authToken":"stub-token","dataSource":"postgresql"}`))
	}))
	t.Cleanup(broker.Close)
	guac := &GuacamoleClient{
		baseURL: broker.URL, publicBaseURL: broker.URL, username: "guacadmin", password: "guacadmin",
		httpClient: resilience.NewResilientHTTPClient(broker.Client(),
			resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
				Name: "guacamole-route-test", Threshold: 5, ResetTimeout: time.Second, Logger: zap.NewNop(),
			})),
		db: db, logger: zap.NewNop(), component: "guacamole",
	}
	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger, guacamoleClient: guac,
		auditService: NewUnifiedAuditService(db, logger)}

	as := func(orgID, userID string, roles ...string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.POST("/guacamole/connections/:routeId/connect", svc.handleGuacamoleConnect)
		r.POST("/guacamole/connections/:routeId/request", svc.handleRequestGuacSession)
		r.PUT("/guacamole/connections/:routeId/credential", svc.handleSetGuacCredential)
		r.POST("/guacamole/session-requests/:id/approve", svc.handleApproveGuacSession)
		r.GET("/guacamole/session-requests", svc.handleListGuacSessionRequests)
		r.GET("/guacamole/my-connections", svc.handleListMyGuacConnections)
		r.GET("/guacamole/my-session-requests", svc.handleListMyGuacSessionRequests)
		r.POST("/pam/entries/:id/grants", svc.handlePamAddEntryGrant)
		return r
	}
	call := func(r *gin.Engine, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	connect := func(userID string, roles ...string) (int, map[string]interface{}) {
		t.Helper()
		return call(as(org, userID, roles...), http.MethodPost, "/guacamole/connections/"+routeID+"/connect", "{}")
	}
	listed := func(userID string, roles ...string) bool {
		t.Helper()
		code, body := call(as(org, userID, roles...), http.MethodGet, "/guacamole/my-connections", "")
		if code != http.StatusOK {
			t.Fatalf("my-connections as %s: %d %v", userID, code, body)
		}
		conns, _ := body["connections"].([]interface{})
		for _, c := range conns {
			if m, ok := c.(map[string]interface{}); ok && m["route_id"] == routeID {
				return true
			}
		}
		return false
	}
	sessionsOf := func(userID string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM pam_entry_sessions s JOIN pam_entries e ON e.id = s.entry_id
			 WHERE e.proxy_route_id = $1::uuid AND s.user_id = $2::uuid`, routeID, userID).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		return n
	}

	// Nobody has been granted anything: a user of the organization who knows
	// the route id neither sees it nor launches it. An administrator does both.
	t.Run("an ungranted user is refused and sees nothing", func(t *testing.T) {
		if listed(stranger) {
			t.Error("my-connections lists the route for a user with no grant")
		}
		if code, body := connect(stranger); code != http.StatusForbidden {
			t.Fatalf("connect = %d %v, want 403", code, body)
		}
		if n := sessionsOf(stranger); n != 0 {
			t.Errorf("the refused launch left %d session rows", n)
		}
	})
	t.Run("an administrator sees the route and launches it through the entry", func(t *testing.T) {
		if !listed(admin, "admin") {
			t.Error("my-connections does not list the route for an administrator")
		}
		code, body := connect(admin, "admin")
		if code != http.StatusOK {
			t.Fatalf("connect = %d %v, want 200", code, body)
		}
		if body["connect_url"] == "" || body["route_id"] != routeID || body["entry_id"] == "" || body["launch_type"] != "guacamole" {
			t.Errorf("the launch answered %v; want a connect URL, the route, the entry and the launch type", body)
		}
		if body["connection_id"] != guacID {
			t.Errorf("connection_id = %v, want the route's provisioned %s", body["connection_id"], guacID)
		}
		if n := sessionsOf(admin); n != 1 {
			t.Errorf("the launch left %d pam_entry_sessions rows, want 1", n)
		}
	})

	// The entry the first launch made stands for the route.
	var entryID string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id::text FROM pam_entries WHERE proxy_route_id = $1::uuid AND org_id = $2::uuid`, routeID, org).Scan(&entryID); err != nil {
		t.Fatalf("the route has no entry: %v", err)
	}
	adminAPI := as(org, admin, "admin")
	if code, body := call(adminAPI, http.MethodPost, "/pam/entries/"+entryID+"/grants",
		`{"principal_type":"user","principal_id":"`+granted+`","actions":["connect"]}`); code != http.StatusCreated {
		t.Fatalf("grant: %d %v", code, body)
	}

	t.Run("a granted user sees the route and launches it", func(t *testing.T) {
		if !listed(granted) {
			t.Error("my-connections does not list the route for the granted user")
		}
		if code, body := connect(granted); code != http.StatusOK {
			t.Fatalf("connect = %d %v, want 200", code, body)
		}
		if n := sessionsOf(granted); n != 1 {
			t.Errorf("the launch left %d pam_entry_sessions rows, want 1", n)
		}
	})

	// The route's credential settings reach the entry: with approval required,
	// the granted user needs a request approved by somebody else, once.
	t.Run("approval saved on the route gates the entry launch, single use", func(t *testing.T) {
		if code, body := call(adminAPI, http.MethodPut, "/guacamole/connections/"+routeID+"/credential",
			`{"require_approval":true,"record_session":true}`); code != http.StatusOK {
			t.Fatalf("set credential: %d %v", code, body)
		}
		code, body := connect(granted)
		if code != http.StatusForbidden || body["approval_required"] != true {
			t.Fatalf("connect without an approval = %d %v, want 403 approval_required", code, body)
		}

		grantedAPI := as(org, granted)
		code, body = call(grantedAPI, http.MethodPost, "/guacamole/connections/"+routeID+"/request", `{"reason":"patching"}`)
		reqID, _ := body["request_id"].(string)
		if code != http.StatusCreated || reqID == "" {
			t.Fatalf("request: %d %v", code, body)
		}
		if code, body := call(as(org, stranger), http.MethodPost, "/guacamole/connections/"+routeID+"/request", `{}`); code != http.StatusForbidden {
			t.Errorf("a request from an ungranted user = %d %v, want 403", code, body)
		}

		// The queue the Privileged Sessions page reads, and the requester's own list.
		code, body = call(adminAPI, http.MethodGet, "/guacamole/session-requests", "")
		queue, _ := body["requests"].([]interface{})
		if code != http.StatusOK || len(queue) != 1 {
			t.Fatalf("session-requests = %d %v, want the one pending request", code, body)
		}
		if row, _ := queue[0].(map[string]interface{}); row["id"] != reqID || row["connection_id"] != connectionPK || row["reason"] != "patching" {
			t.Errorf("the queue row is %v; want the request keyed on the route's connection record", queue[0])
		}
		code, body = call(grantedAPI, http.MethodGet, "/guacamole/my-session-requests", "")
		mine, _ := body["requests"].([]interface{})
		if code != http.StatusOK || len(mine) != 1 {
			t.Fatalf("my-session-requests = %d %v, want 1", code, body)
		}
		if row, _ := mine[0].(map[string]interface{}); row["route_id"] != routeID || row["status"] != "pending" {
			t.Errorf("my request row is %v; want it pending on the route", mine[0])
		}
		if code, body := call(as(org, stranger), http.MethodGet, "/guacamole/my-session-requests", ""); code != http.StatusOK || len(body["requests"].([]interface{})) != 0 {
			t.Errorf("another user's list = %d %v, want empty", code, body)
		}

		// Four eyes: the requester cannot approve; another administrator can.
		if code, body := call(as(org, granted, "admin"), http.MethodPost, "/guacamole/session-requests/"+reqID+"/approve", "{}"); code != http.StatusForbidden {
			t.Errorf("self-approval = %d %v, want 403", code, body)
		}
		if code, body := call(as(org, approver, "admin"), http.MethodPost, "/guacamole/session-requests/"+reqID+"/approve", "{}"); code != http.StatusOK {
			t.Fatalf("approve = %d %v", code, body)
		}

		if code, body := connect(granted); code != http.StatusOK || body["recorded"] != true {
			t.Fatalf("connect with an approval = %d %v, want 200 recorded", code, body)
		}
		if code, body := connect(granted); code != http.StatusForbidden {
			t.Fatalf("a second connect on the consumed approval = %d %v, want 403", code, body)
		}

		// The recorded launch is on both ledgers: the entry's, and the route's,
		// which the Privileged Sessions page and the retention sweep read.
		var recordings int
		if err := db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM guacamole_sessions
			 WHERE connection_id = $1::uuid AND user_id = $2::uuid AND recording_path <> ''`, connectionPK, granted).Scan(&recordings); err != nil {
			t.Fatalf("count guacamole_sessions: %v", err)
		}
		if recordings != 1 {
			t.Errorf("guacamole_sessions holds %d recorded rows for the launch, want 1", recordings)
		}
	})

	t.Run("another tenant's administrator finds no route", func(t *testing.T) {
		code, body := call(as(otherOrg, admin, "admin"), http.MethodPost, "/guacamole/connections/"+routeID+"/connect", "{}")
		if code != http.StatusNotFound {
			t.Fatalf("connect from the other tenant = %d %v, want 404", code, body)
		}
		if strings.Contains(fmt.Sprint(body), guacID) || strings.Contains(fmt.Sprint(body), "198.51.100.9") {
			t.Errorf("the refusal named the connection or the host: %v", body)
		}
	})
}
