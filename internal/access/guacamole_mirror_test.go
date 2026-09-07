package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
)

// A live Guacamole connection nothing brokers to.
//
// provisionGuacamoleForRoute creates the connection in Guacamole, saves the
// mapping row, and then writes proxy_routes.guacamole_connection_id. That last
// column does two jobs: it is what the route brokers to, and it is what stops
// the next provision creating another connection. The write was unchecked.
//
// So losing it costs twice. The route cannot broker a session -- the connection
// exists and nothing points at it -- and every later touch of the route creates
// a fresh duplicate in Guacamole, because the check for "already provisioned"
// reads the column that was never written.

// guacStub is a fake Guacamole REST API: it answers connection creation and
// records what it was asked to create, so a test can say the connection really
// exists while the route does not name it.
type guacStub struct {
	*httptest.Server

	mu      sync.Mutex
	created []string // connection names, in order
}

func newGuacStub(t *testing.T) *guacStub {
	t.Helper()
	g := &guacStub{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/connections") {
			g.mu.Lock()
			g.created = append(g.created, r.URL.Path)
			g.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"identifier":"conn-1","name":"openidx-ssh-a-host"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *guacStub) createdCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.created)
}

// guacClientAgainst builds a client pointed at the stub. A struct literal
// rather than NewGuacamoleClient for the same reason as the Ziti stub: the
// constructor authenticates, and none of these tests are about that.
func guacClientAgainst(t *testing.T, stub *guacStub, db *database.PostgresDB) *GuacamoleClient {
	t.Helper()
	return &GuacamoleClient{
		baseURL:       stub.URL,
		publicBaseURL: stub.URL,
		dataSource:    "postgresql",
		authToken:     "stub-token",
		httpClient: resilience.NewResilientHTTPClient(
			&http.Client{Timeout: 5 * time.Second}, guacBreaker("test", zap.NewNop())),
		db:        db,
		logger:    zap.NewNop(),
		component: "guacamole",
	}
}

const guacMirrorSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), route_type VARCHAR(32),
    remote_host VARCHAR(255), remote_port INTEGER,
    guacamole_connection_id VARCHAR(255),
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
CREATE TABLE IF NOT EXISTS guacamole_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id UUID UNIQUE, org_id UUID,
    guacamole_connection_id VARCHAR(255), protocol VARCHAR(32),
    hostname VARCHAR(255), port INTEGER, parameters JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());`

const (
	guacMirrorOrg   = "00000000-0000-0000-0000-0000000000e1"
	guacMirrorRoute = "00000000-0000-0000-0000-0000000000e2"
)

func guacMirrorFixture(t *testing.T) (*Service, *guacStub, *database.PostgresDB, context.Context, *ProxyRoute, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, nil, func() {}
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: guacMirrorOrg})

	if _, err := db.Pool.Exec(ctx, guacMirrorSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (id, name, route_type, remote_host, remote_port, org_id)
		 VALUES ($1::uuid, 'a-host', 'ssh', 'jump.internal', 22, $2::uuid)`,
		guacMirrorRoute, guacMirrorOrg); err != nil {
		cleanup()
		t.Fatalf("seed the route: %v", err)
	}

	stub := newGuacStub(t)
	svc := &Service{
		db:              db,
		logger:          zap.NewNop(),
		guacamoleClient: guacClientAgainst(t, stub, db),
	}
	route := &ProxyRoute{
		ID: guacMirrorRoute, Name: "a-host", RouteType: "ssh",
		RemoteHost: "jump.internal", RemotePort: 22,
	}
	return svc, stub, db, ctx, route, cleanup
}

func TestProvisioningGuacamolePointsTheRouteAtTheConnection(t *testing.T) {
	s, stub, db, ctx, route, cleanup := guacMirrorFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if err := s.provisionGuacamoleForRoute(ctx, route); err != nil {
		t.Fatalf("provisioning Guacamole: %v", err)
	}
	if stub.createdCount() != 1 {
		t.Fatalf("%d connections created in Guacamole, want 1", stub.createdCount())
	}

	var connID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT guacamole_connection_id FROM proxy_routes WHERE id = $1::uuid`, guacMirrorRoute).Scan(&connID); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if connID == nil || *connID != "conn-1" {
		t.Errorf("the route names connection %v after a successful provision; this column is what it "+
			"brokers to", connID)
	}
}

// The case the old code returned nil from: the connection is live in Guacamole
// and the route does not know its id.
func TestAGuacamoleProvisionThatCannotPointTheRouteAtItDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, route, cleanup := guacMirrorFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "proxy_routes", "UPDATE")

	err := s.provisionGuacamoleForRoute(ctx, route)
	if err == nil {
		t.Fatal("the connection was created in Guacamole, the route was not pointed at it, and " +
			"provisioning reported success")
	}
	if !strings.Contains(err.Error(), "provisioned again on the next attempt") {
		t.Errorf("the error does not say the route will provision a duplicate next time, which is the "+
			"cost that accumulates silently: %v", err)
	}
	// The Guacamole half really happened; without this the test would pass on
	// any earlier failure.
	if stub.createdCount() != 1 {
		t.Errorf("%d connections were created in Guacamole, so this proves nothing about the split",
			stub.createdCount())
	}

	var connID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT guacamole_connection_id FROM proxy_routes WHERE id = $1::uuid`, guacMirrorRoute).Scan(&connID); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if connID != nil {
		t.Errorf("the route names %q; the test's premise (the write was refused) did not hold", *connID)
	}
}
