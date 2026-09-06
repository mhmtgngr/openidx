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
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the PAM broker's connection registry, migration v151.
//
// A guacamole_connections row is the definition of a privileged session
// target: host, port, protocol, the vault secret injected into the session,
// and whether an approval, a moderator or a recording is required. Until v151
// it carried no org_id and no belt, and handleGuacamoleConnect — which any
// authenticated user may call — resolved the caller's organization, refused
// when there was none, and then loaded the target row by route id alone:
//
//	SELECT id, guacamole_connection_id, protocol, hostname, port,
//	       COALESCE(vault_secret_id::text,''), ...
//	  FROM guacamole_connections WHERE route_id=$1
//
// Everything after that acts on whatever row came back. The row's vault secret
// is read under orgctx.WithBypassRLS (deliberately — the server has to be able
// to inject it), pushed into the broker as connection parameters, and a
// connect URL is returned. So this was not a disclosure but an escalation: a
// user of one tenant, holding nothing but another tenant's route id, got a
// live RDP/SSH/VNC session onto that tenant's host with that tenant's
// credential typed in for them.
func TestGuacamoleConnections_TenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('guac-b','guac-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedRoute := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
			VALUES ($1::uuid, $2, $3, 'ssh://internal.corp:22', true)
			RETURNING id::text`,
			org, name, "https://"+name+".example.test").Scan(&id); err != nil {
			t.Fatalf("seed route %s: %v", name, err)
		}
		return id
	}
	seedConn := func(org, routeID, guacID, hostname string, requireApproval bool) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO guacamole_connections
			    (route_id, org_id, guacamole_connection_id, protocol, hostname, port,
			     require_approval, record_session, require_moderator)
			VALUES ($1::uuid, $2::uuid, $3, 'rdp', $4, 3389, $5, false, false)
			RETURNING id::text`,
			routeID, org, guacID, hostname, requireApproval).Scan(&id); err != nil {
			t.Fatalf("seed connection %s: %v", guacID, err)
		}
		return id
	}

	routeA := seedRoute(orgA, "gc-a-"+suffix)
	routeB := seedRoute(orgB, "gc-b-"+suffix)
	const hostA = "198.51.100.9"
	guacA := "guac-a-" + suffix
	connA := seedConn(orgA, routeA, guacA, hostA, true) // approval required
	seedConn(orgB, routeB, "guac-b-"+suffix, "198.51.100.11", false)

	// A broker stub so the handler's success path is deterministic and offline.
	// perUserIdentities is false, so the only call it makes is the token mint.
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authToken":"stub-token","dataSource":"postgresql"}`))
	}))
	defer broker.Close()
	guac := &GuacamoleClient{
		baseURL:       broker.URL,
		publicBaseURL: broker.URL,
		username:      "guacadmin",
		password:      "guacadmin",
		httpClient: resilience.NewResilientHTTPClient(broker.Client(),
			resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
				Name: "guacamole-test", Threshold: 5, ResetTimeout: time.Second, Logger: zap.NewNop(),
			})),
		db:        db,
		logger:    zap.NewNop(),
		component: "guacamole",
	}
	s := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}, guacamoleClient: guac}

	const userA = "00000000-0000-0000-0000-0000000000a1"
	const userB = "00000000-0000-0000-0000-0000000000b2"

	call := func(org, user string, fn gin.HandlerFunc, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("org_id", org)
		c.Set("user_id", user)
		fn(c)
		return w
	}

	// THE ESCALATION.
	t.Run("a connect against another tenant's route is refused at the row", func(t *testing.T) {
		// Model the pre-v151 world exactly: org B's own administrator has
		// approved org B's user for org A's connection. handleRequestGuacSession
		// resolves the connection org-scoped since v151, so the row is seeded
		// directly here — the point is that NOTHING about this row is out of
		// place inside org B. It carries org B's org_id, org B's requester, and
		// org B approved it.
		var reqID string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO guacamole_session_requests
			    (org_id, connection_id, requester_id, reason, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'four-eyes at home', 'approved', NOW() + INTERVAL '1 hour')
			RETURNING id::text`, orgB, connA, userB).Scan(&reqID); err != nil {
			t.Fatalf("seed org B approval against org A's connection: %v", err)
		}

		w := call(orgB, userB, s.handleGuacamoleConnect, http.MethodPost,
			"/guacamole/connections/"+routeA+"/connect", "{}",
			gin.Params{{Key: "routeId", Value: routeA}})

		if w.Code != http.StatusNotFound {
			t.Fatalf("org B connecting to org A's route returned %d %s; it must be 404. This "+
				"handler reads the row's vault_secret_id under bypass-RLS and injects the "+
				"credential into the session, so a row reachable across tenants is a live "+
				"RDP/SSH/VNC session onto another tenant's host with that tenant's password",
				w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), guacA) || strings.Contains(w.Body.String(), hostA) {
			t.Fatalf("org A's broker connection id or hostname leaked into org B's response: %s", w.Body.String())
		}

		// And the refusal happened at the connection, not at the approval gate.
		// checkAndConsumeApproval would have matched this row — it keys on
		// (connection_id, requester_id) over a table belted to the CALLER's
		// organization, which is exactly why it could not help: the four-eyes
		// control is satisfiable without ever leaving home. A still-'approved'
		// row proves the lookup refused first.
		var status string
		if err := db.Pool.QueryRow(ctx,
			`SELECT status FROM guacamole_session_requests WHERE id = $1`, reqID).Scan(&status); err != nil {
			t.Fatalf("read back the approval: %v", err)
		}
		if status != "approved" {
			t.Fatalf("the approval was consumed (status %q): the request reached the gate, so the "+
				"gate is what refused it. It cannot be relied on — org B approved this itself", status)
		}
	})

	// The predicate must scope, not empty.
	t.Run("the owning tenant can still connect", func(t *testing.T) {
		// Give org A a real approval so the gate passes for its own user.
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO guacamole_session_requests
			    (org_id, connection_id, requester_id, reason, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'own tenant', 'approved', NOW() + INTERVAL '1 hour')`,
			orgA, connA, userA); err != nil {
			t.Fatalf("seed org A approval: %v", err)
		}

		w := call(orgA, userA, s.handleGuacamoleConnect, http.MethodPost,
			"/guacamole/connections/"+routeA+"/connect", "{}",
			gin.Params{{Key: "routeId", Value: routeA}})
		if w.Code != http.StatusOK {
			t.Fatalf("org A connecting to its OWN route returned %d %s; the org predicate must "+
				"scope the lookup, not empty it", w.Code, w.Body.String())
		}
		var got struct {
			ConnectURL   string `json:"connect_url"`
			ConnectionID string `json:"connection_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("bad json: %s", w.Body.String())
		}
		if got.ConnectionID != guacA {
			t.Fatalf("org A got connection %q, want its own %q", got.ConnectionID, guacA)
		}
		if got.ConnectURL == "" {
			t.Fatal("org A got no connect URL")
		}
	})

	// THE DISCLOSURE.
	t.Run("the connection list is per org", func(t *testing.T) {
		conns, err := s.guacamoleClient.ListGuacConnections(
			orgctx.With(context.Background(), orgctx.Org{ID: orgB}))
		if err != nil {
			t.Fatalf("org B list: %v", err)
		}
		for _, c := range conns {
			if c.Hostname == hostA || c.GuacamoleConnectionID == guacA {
				t.Fatalf("org B sees org A's brokered target %s:%d (%s). This query had no WHERE "+
					"clause: every tenant's internal hostnames, ports and connection parameters",
					c.Hostname, c.Port, c.GuacamoleConnectionID)
			}
		}
		if len(conns) != 1 {
			t.Fatalf("org B should see exactly its own connection, got %d", len(conns))
		}

		conns, err = s.guacamoleClient.ListGuacConnections(
			orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
		if err != nil {
			t.Fatalf("org A list: %v", err)
		}
		if len(conns) != 1 || conns[0].GuacamoleConnectionID != guacA {
			t.Fatalf("org A should see exactly its own connection, got %d", len(conns))
		}
	})

	// The write side: the PAM configuration of another tenant's target.
	//
	// WHAT THIS ONE CANNOT PROVE: it is green against the pre-v151 handler too.
	// handleSetGuacCredential already gated on an EXISTS over
	// guacamole_connections JOIN proxy_routes with the route's org_id, so the
	// write was scoped where the read next to it was not — the two halves of one
	// feature disagreeing, the shape v146 and v149 both found. v151 adds
	// gc.org_id alongside and puts the predicate on the UPDATE itself; this case
	// pins the behaviour so a later edit cannot drop the older guard now that a
	// belt exists to be leaned on.
	t.Run("another tenant cannot repoint the injected credential", func(t *testing.T) {
		w := call(orgB, userB, s.handleSetGuacCredential, http.MethodPut,
			"/guacamole/connections/"+routeA+"/credential",
			`{"inject_username":"attacker","require_approval":false,"record_session":false}`,
			gin.Params{{Key: "routeId", Value: routeA}})
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B setting the credential config on org A's connection returned %d %s; "+
				"it must be 404", w.Code, w.Body.String())
		}

		var injectUser *string
		var requireApproval bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT inject_username, require_approval FROM guacamole_connections WHERE id = $1`,
			connA).Scan(&injectUser, &requireApproval); err != nil {
			t.Fatalf("read back org A's connection: %v", err)
		}
		if injectUser != nil {
			t.Fatalf("org A's inject_username was rewritten to %q by another tenant", *injectUser)
		}
		if !requireApproval {
			t.Fatal("org A's require_approval was turned off by another tenant: the approval gate " +
				"can be disabled from outside the tenant it protects")
		}
	})

	// The moderation request keys the four-eyes gate, so it needs the same scope.
	t.Run("a moderation request cannot name another tenant's connection", func(t *testing.T) {
		before := countModerationRows(t, db, ctx)
		w := call(orgB, userB, s.handleRequestModeration, http.MethodPost,
			"/pam/moderation/request", `{"route_id":"`+routeA+`","reason":"x"}`, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B opening a moderation request against org A's connection returned "+
				"%d %s; it must be 404. checkModerationActive matches this row over a belted "+
				"table, so org B would have satisfied its own four-eyes gate",
				w.Code, w.Body.String())
		}
		if after := countModerationRows(t, db, ctx); after != before {
			t.Fatalf("a moderation row was written anyway (%d -> %d)", before, after)
		}
	})
}

func countModerationRows(t *testing.T, db *database.PostgresDB, ctx context.Context) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM guacamole_moderation_sessions`).Scan(&n); err != nil {
		t.Fatalf("count moderation rows: %v", err)
	}
	return n
}
