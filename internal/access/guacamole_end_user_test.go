package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestGuacEndUserSelfService proves the end-user self-service handlers:
// my-connections lists the org's brokered connections with their PAM flags,
// and my-session-requests returns only the caller's own requests (never
// another user's), joined with route info. Uses a migrated testcontainer DB
// (container superuser bypasses RLS, so the handlers' explicit org_id/user
// predicates carry the scoping).
func TestGuacEndUserSelfService(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	const userA = "11111111-1111-1111-1111-111111111111"
	const userB = "22222222-2222-2222-2222-222222222222"

	// Seed a route + brokered connection with PAM flags on.
	var routeID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1::uuid, 'prod-db-bastion', 'https://bastion.example.test', 'ssh://10.0.0.5', true)
		RETURNING id::text`, defaultOrg).Scan(&routeID); err != nil {
		t.Fatalf("seed proxy route: %v", err)
	}
	var connectionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_connections
			(route_id, guacamole_connection_id, protocol, hostname, port, require_approval, record_session)
		VALUES ($1::uuid, 'guac-conn-1', 'ssh', '10.0.0.5', 22, true, true)
		RETURNING id::text`, routeID).Scan(&connectionID); err != nil {
		t.Fatalf("seed guacamole connection: %v", err)
	}

	// One request each for two different users.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO guacamole_session_requests (org_id, connection_id, requester_id, reason, status)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'deploy hotfix', 'approved'),
		       ($1::uuid, $2::uuid, $4::uuid, 'other user',    'pending')`,
		defaultOrg, connectionID, userA, userB); err != nil {
		t.Fatalf("seed session requests: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	// my-connections: the seeded connection shows up with its PAM flags.
	conns := fetchMyConnections(t, s, defaultOrg)
	if len(conns) != 1 {
		t.Fatalf("my-connections returned %d connections, want 1", len(conns))
	}
	got := conns[0]
	if got.RouteID != routeID || got.Name != "prod-db-bastion" || got.Protocol != "ssh" {
		t.Errorf("connection = %+v, want route %s / prod-db-bastion / ssh", got, routeID)
	}
	if !got.RequireApproval || !got.RecordSession {
		t.Errorf("PAM flags = approval:%v record:%v, want both true", got.RequireApproval, got.RecordSession)
	}
	if got.CredentialInjected {
		t.Errorf("credential_injected = true, want false (no vault_secret_id set)")
	}

	// my-session-requests: user A sees only their own approved request.
	reqs := fetchMySessionRequests(t, s, defaultOrg, userA)
	if len(reqs) != 1 {
		t.Fatalf("my-session-requests for user A returned %d rows, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Status != "approved" || r.Reason != "deploy hotfix" {
		t.Errorf("request = %+v, want status approved / reason 'deploy hotfix'", r)
	}
	if r.RouteID != routeID || r.RouteName != "prod-db-bastion" || r.Protocol != "ssh" {
		t.Errorf("request join = %+v, want route %s / prod-db-bastion / ssh", r, routeID)
	}

	// A disabled route disappears from the end-user catalog.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE proxy_routes SET enabled = false WHERE id = $1::uuid`, routeID); err != nil {
		t.Fatalf("disable route: %v", err)
	}
	if conns := fetchMyConnections(t, s, defaultOrg); len(conns) != 0 {
		t.Errorf("my-connections after disabling route returned %d, want 0", len(conns))
	}
}

// fetchMyConnections drives handleListMyGuacConnections over a gin test context.
func fetchMyConnections(t *testing.T, s *Service, orgID string) []GuacUserConnection {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/guacamole/my-connections", nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
	c.Request = req

	s.handleListMyGuacConnections(c)
	if w.Code != http.StatusOK {
		t.Fatalf("my-connections handler status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Connections []GuacUserConnection `json:"connections"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal my-connections response: %v", err)
	}
	return resp.Connections
}

// fetchMySessionRequests drives handleListMyGuacSessionRequests as the given user.
func fetchMySessionRequests(t *testing.T, s *Service, orgID, userID string) []GuacMySessionRequest {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/guacamole/my-session-requests", nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
	c.Request = req
	c.Set("user_id", userID)

	s.handleListMyGuacSessionRequests(c)
	if w.Code != http.StatusOK {
		t.Fatalf("my-session-requests handler status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Requests []GuacMySessionRequest `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal my-session-requests response: %v", err)
	}
	return resp.Requests
}
