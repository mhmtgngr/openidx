package access

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The BrowZer half of "the network changed, the record did not".
//
// Three of the fixes from e2ea1ebe live here, and BrowZer makes the class
// unusually visible, because a proxy_routes row is not just a record OF the
// published service -- RegenerateConfigs builds the published BrowZer target
// list FROM that table, a few lines below each of these writes. So the row is
// the publication. Disable BrowZer on a service, lose the row deletion, and the
// very next config regeneration republishes the service the API just said had
// been withdrawn.
//
// The two replacements are the other direction. from_url carries no unique
// constraint, so delete-then-insert with the delete unchecked leaves two
// BrowZer routes for one service and nothing in the router or the generated
// config that decides which one wins.

const zitiBrowzerSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), description TEXT, from_url TEXT, to_url TEXT,
    require_auth BOOLEAN DEFAULT true, enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 10,
    ziti_enabled BOOLEAN DEFAULT false, ziti_service_name VARCHAR(255),
    browzer_enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255),
    host VARCHAR(255), port INTEGER, org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_browzer_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_jwt_signer_id VARCHAR(255), auth_policy_id VARCHAR(255),
    dial_policy_id VARCHAR(255), oidc_issuer TEXT, oidc_client_id VARCHAR(255),
    enabled BOOLEAN DEFAULT false, updated_at TIMESTAMPTZ DEFAULT NOW());`

const (
	browzerOrg    = "00000000-0000-0000-0000-0000000000b1"
	browzerZitiID = "svc-b1"
	browzerName   = "a-service"
)

// browzerFixture seeds one Ziti service that already has a BrowZer route in
// front of it, a BrowZer config to disable, and a controller that takes the
// role-attribute patch and every teardown call.
func browzerFixture(t *testing.T) (*Service, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: browzerOrg})

	if _, err := db.Pool.Exec(ctx, zitiBrowzerSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO ziti_services (ziti_id, name, host, port, org_id)
		  VALUES ($1, $2, 'app.internal', 8080, $3::uuid)`,
			[]any{browzerZitiID, browzerName, browzerOrg}},
		{`INSERT INTO proxy_routes (name, from_url, to_url, ziti_enabled, ziti_service_name, browzer_enabled, org_id)
		  VALUES ('browzer-a-service', 'http://browzer.localtest.me/old', 'http://app.internal:8080',
		          true, $1, true, $2::uuid)`,
			[]any{browzerName, browzerOrg}},
		{`INSERT INTO ziti_browzer_config (external_jwt_signer_id, auth_policy_id, dial_policy_id, enabled)
		  VALUES ('signer-1', 'authpol-1', 'dialpol-1', true)`, nil},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			cleanup()
			t.Fatalf("seed: %v", err)
		}
	}

	stub := newZitiStub(t)
	stub.ok("GET /edge/management/v1/services/"+browzerZitiID,
		`{"data":{"id":"`+browzerZitiID+`","name":"`+browzerName+`","roleAttributes":["browzer-enabled"]}}`)
	for _, pattern := range []string{
		"PATCH /edge/management/v1/services",
		"DELETE /edge/management/v1/service-policies",
		"DELETE /edge/management/v1/auth-policies",
		"DELETE /edge/management/v1/external-jwt-signers",
	} {
		stub.on(pattern, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}

	svc := &Service{
		db:           db,
		logger:       zap.NewNop(),
		zitiProvider: newZitiProviderWith(zitiManagerAgainst(t, stub, db)),
	}
	return svc, stub, db, ctx, cleanup
}

// browzerRoutes returns how many BrowZer routes name this service, which is the
// number the generated config publishes.
func browzerRoutes(t *testing.T, db *database.PostgresDB, ctx context.Context) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM proxy_routes WHERE ziti_service_name = $1 AND browzer_enabled = true`,
		browzerName).Scan(&n); err != nil {
		t.Fatalf("count BrowZer routes: %v", err)
	}
	return n
}

// The positive control: enabling with a path replaces the route rather than
// adding to it, so exactly one route publishes the service.
func TestEnablingBrowZerOnAServiceReplacesItsPathRoute(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := call(t, s, ctx, http.MethodPost, browzerZitiID,
		map[string]any{"path": "/app"}, s.handleEnableBrowZerOnService)
	if w.Code != http.StatusOK {
		t.Fatalf("enabling BrowZer on a service answered %d: %s (controller saw %v)",
			w.Code, w.Body.String(), stub.received())
	}
	if !stub.saw("PATCH /edge/management/v1/services/" + browzerZitiID) {
		t.Errorf("the service's role attributes were never patched; calls: %v", stub.received())
	}
	if n := browzerRoutes(t, db, ctx); n != 1 {
		t.Errorf("%d BrowZer routes publish %q after a replacement; there is no defined winner between "+
			"them in the route table or the generated config", n, browzerName)
	}

	var fromURL string
	if err := db.Pool.QueryRow(ctx,
		`SELECT from_url FROM proxy_routes WHERE ziti_service_name = $1`, browzerName).Scan(&fromURL); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if !strings.HasSuffix(fromURL, "/app") {
		t.Errorf("the surviving route is %q, not the one just asked for", fromURL)
	}
}

// The case the old code inserted through: the delete fails, and the insert
// would make a second route for the same service.
func TestABrowZerPathRouteThatCannotBeReplacedIsNotDuplicated(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "proxy_routes", "DELETE")

	w := call(t, s, ctx, http.MethodPost, browzerZitiID,
		map[string]any{"path": "/app"}, s.handleEnableBrowZerOnService)
	if w.Code == http.StatusOK {
		t.Fatalf("the old route could not be deleted and the handler answered 200: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "could not be replaced") {
		t.Errorf("the response does not say the route was not replaced, so an operator cannot tell "+
			"which half of the change landed: %s", w.Body.String())
	}
	// The controller half really happened — without this the test would pass on
	// any early return, and the split is the whole point.
	if !stub.saw("PATCH /edge/management/v1/services/" + browzerZitiID) {
		t.Errorf("the role attributes were never patched; calls: %v", stub.received())
	}
	if n := browzerRoutes(t, db, ctx); n != 1 {
		t.Errorf("%d BrowZer routes for %q: the handler inserted a second one over a delete that failed",
			n, browzerName)
	}
}

// The vhost route is a separate replacement with the same shape, and its own
// delete, so it needs its own case.
func TestABrowZerVhostRouteThatCannotBeReplacedIsNotDuplicated(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	// The vhost replacement deletes by route NAME, so seed the row it will try
	// to remove.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (name, from_url, to_url, ziti_enabled, ziti_service_name, browzer_enabled, org_id)
		 VALUES ('browzer-vhost-'||$1, 'http://old.example.test/', 'http://app.internal:8080',
		         true, $1, true, $2::uuid)`, browzerName, browzerOrg); err != nil {
		t.Fatalf("seed the vhost route: %v", err)
	}
	refuseWrites(t, db, ctx, "proxy_routes", "DELETE")

	w := call(t, s, ctx, http.MethodPost, browzerZitiID,
		map[string]any{"domain": "app.example.test"}, s.handleEnableBrowZerOnService)
	if w.Code == http.StatusOK {
		t.Fatalf("the old vhost route could not be deleted and the handler answered 200: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "could not be replaced") {
		t.Errorf("the response does not say the vhost route was not replaced: %s", w.Body.String())
	}
	if !stub.saw("PATCH /edge/management/v1/services/" + browzerZitiID) {
		t.Errorf("the role attributes were never patched; calls: %v", stub.received())
	}
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM proxy_routes WHERE name = 'browzer-vhost-'||$1`, browzerName).Scan(&n); err != nil {
		t.Fatalf("count vhost routes: %v", err)
	}
	if n != 1 {
		t.Errorf("%d vhost routes named browzer-vhost-%s; two routes for one domain is not a state the "+
			"router can resolve", n, browzerName)
	}
}

// Disabling: the row IS the publication, so a lost delete republishes the
// service the API just said was withdrawn.
func TestDisablingBrowZerOnAServiceThatKeepsItsRouteDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "proxy_routes", "DELETE")

	w := call(t, s, ctx, http.MethodPost, browzerZitiID, nil, s.handleDisableBrowZerOnService)
	if w.Code == http.StatusOK {
		t.Fatalf("BrowZer was taken off the service on the controller, its route row survived, and the "+
			"handler answered 200. The next config regeneration republishes it: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "still published to BrowZer") {
		t.Errorf("the response does not say the service is still published, which is the one thing an "+
			"operator has to go and undo: %s", w.Body.String())
	}
	if !stub.saw("PATCH /edge/management/v1/services/" + browzerZitiID) {
		t.Errorf("the role attributes were never patched; calls: %v", stub.received())
	}
	if n := browzerRoutes(t, db, ctx); n != 1 {
		t.Errorf("%d BrowZer routes survive; the test's premise (the delete was refused) did not hold", n)
	}
}

func TestDisablingBrowZerOnAServiceRemovesItsRoute(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := call(t, s, ctx, http.MethodPost, browzerZitiID, nil, s.handleDisableBrowZerOnService)
	if w.Code != http.StatusOK {
		t.Fatalf("disabling BrowZer on a service answered %d: %s (controller saw %v)",
			w.Code, w.Body.String(), stub.received())
	}
	if n := browzerRoutes(t, db, ctx); n != 0 {
		t.Errorf("%d BrowZer routes survive a successful disable, and the generated config is built from "+
			"exactly those rows", n)
	}
}

// The install-wide disable. The external JWT signer is gone by the time the row
// is written, so BrowZer cannot authenticate anybody whatever the row says.
func TestABrowZerDisableThatCannotWriteItsConfigDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "ziti_browzer_config", "UPDATE")

	err := s.ziti().DisableBrowZer(ctx)
	if err == nil {
		t.Fatal("the signer was deleted on the controller, the config still records BrowZer as enabled, " +
			"and DisableBrowZer reported success")
	}
	if !strings.Contains(err.Error(), "no signer behind it") {
		t.Errorf("the error does not say the console will show BrowZer as on with nothing behind it, "+
			"which is the state nobody can see from the console: %v", err)
	}
	if !stub.saw("DELETE /edge/management/v1/external-jwt-signers/signer-1") {
		t.Errorf("the signer was never deleted, so this proves nothing about the split; calls: %v",
			stub.received())
	}

	var enabled bool
	if err := db.Pool.QueryRow(ctx, `SELECT enabled FROM ziti_browzer_config LIMIT 1`).Scan(&enabled); err != nil {
		t.Fatalf("read the config back: %v", err)
	}
	if !enabled {
		t.Error("the config was written; the test's premise (the update was refused) did not hold")
	}
}

func TestABrowZerDisableClearsTheConfigWhenNothingRefuses(t *testing.T) {
	s, _, db, ctx, cleanup := browzerFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if err := s.ziti().DisableBrowZer(ctx); err != nil {
		t.Fatalf("DisableBrowZer: %v", err)
	}
	var enabled bool
	if err := db.Pool.QueryRow(ctx, `SELECT enabled FROM ziti_browzer_config LIMIT 1`).Scan(&enabled); err != nil {
		t.Fatalf("read the config back: %v", err)
	}
	if enabled {
		t.Error("BrowZer is still recorded as enabled after a successful disable")
	}
}
