package access

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/database"
)

// The network changed and the record did not.
//
// TeardownZitiForRoute deletes a service's policies and then the service itself
// on the controller, and only afterwards removes the rows that record them.
// Both of those deletes discarded their errors, so a database that refused them
// left ziti_services and ziti_service_policies naming a service the overlay no
// longer has -- listed in the console as live, and treated by the reconciler as
// existing -- while the teardown returned nil.
//
// It is the same shape as the six Ziti handlers fixed in 2dc69b3d and the eight
// more in e2ea1ebe, and it is the first of them to carry a handler test,
// because the fake controller in ziti_stub_test.go finally makes the
// controller half reachable.

const zitiTeardownSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), from_url TEXT, to_url TEXT,
    ziti_enabled BOOLEAN DEFAULT false, ziti_service_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true, require_auth BOOLEAN DEFAULT true,
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), route_id UUID,
    enabled BOOLEAN DEFAULT true, org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), org_id UUID);`

const (
	teardownOrg   = "00000000-0000-0000-0000-0000000000e1"
	teardownRoute = "00000000-0000-0000-0000-0000000000e2"
	teardownSvc   = "a-service"
)

// teardownFixture seeds one route with a Ziti service and a dial policy behind
// it, and a controller that accepts every delete.
func teardownFixture(t *testing.T) (*ZitiManager, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, zitiTeardownSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	// One Exec per statement: pgx prepares anything given arguments, and a
	// prepared statement holds exactly one command.
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO proxy_routes (id, name, ziti_enabled, ziti_service_name, org_id)
		  VALUES ($1::uuid, 'a-route', true, $2, $3::uuid)`,
			[]any{teardownRoute, teardownSvc, teardownOrg}},
		{`INSERT INTO ziti_services (ziti_id, name, route_id, org_id)
		  VALUES ('svc-1', $1, $2::uuid, $3::uuid)`,
			[]any{teardownSvc, teardownRoute, teardownOrg}},
		{`INSERT INTO ziti_service_policies (ziti_id, name, org_id)
		  VALUES ('pol-1', 'openidx-dial-' || $1, $2::uuid)`,
			[]any{teardownSvc, teardownOrg}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			cleanup()
			t.Fatalf("seed: %v", err)
		}
	}

	stub := newZitiStub(t)
	// Everything the teardown asks the controller for.
	stub.on("DELETE /edge/management/v1/service-policies", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stub.on("DELETE /edge/management/v1/services", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// The by-name cleanups look the entity up first; an empty list is a
	// controller that has nothing left to remove.
	stub.ok("GET /edge/management/v1/configs", `{"data":[]}`)
	stub.ok("GET /edge/management/v1/service-edge-router-policies", `{"data":[]}`)

	return zitiManagerAgainst(t, stub, db), stub, db, ctx, cleanup
}

func TestTeardownRemovesTheServiceFromBothSides(t *testing.T) {
	zm, stub, db, ctx, cleanup := teardownFixture(t)
	if zm == nil {
		return
	}
	defer cleanup()

	if err := zm.TeardownZitiForRoute(ctx, teardownRoute); err != nil {
		t.Fatalf("TeardownZitiForRoute: %v (controller saw %v)", err, stub.received())
	}

	if !stub.saw("DELETE /edge/management/v1/services/svc-1") {
		t.Errorf("the service was not deleted on the controller; calls: %v", stub.received())
	}

	for _, table := range []string{"ziti_services", "ziti_service_policies"} {
		var n int
		if err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%d row(s) survive in %s after a teardown; the console will list a service "+
				"the overlay no longer has", n, table)
		}
	}

	var enabled bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_enabled FROM proxy_routes WHERE id = $1::uuid`, teardownRoute).Scan(&enabled); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if enabled {
		t.Error("the route still has ziti_enabled after its service was torn down")
	}
}

// The case the old code reported as success: the controller side is done and
// the rows cannot be removed.
func TestATeardownThatLeavesRecordsBehindSaysSo(t *testing.T) {
	zm, stub, db, ctx, cleanup := teardownFixture(t)
	if zm == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_ziti_service_delete() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_ziti_service_delete_trg BEFORE DELETE ON ziti_services
		FOR EACH ROW EXECUTE FUNCTION refuse_ziti_service_delete();`); err != nil {
		t.Fatalf("install refusal trigger: %v", err)
	}

	err := zm.TeardownZitiForRoute(ctx, teardownRoute)
	if err == nil {
		t.Fatal("the service was deleted on the controller, its row could not be removed, and the " +
			"teardown reported success. The console goes on listing a service the overlay does not " +
			"have, and the reconciler treats it as existing.")
	}
	if !strings.Contains(err.Error(), "ziti_services") {
		t.Errorf("the error does not name what was left behind: %v", err)
	}

	// The controller half really did happen — which is why the error must not
	// read as "the teardown failed".
	if !stub.saw("DELETE /edge/management/v1/services/svc-1") {
		t.Errorf("the service was never deleted on the controller, so this test proves nothing "+
			"about the split; calls: %v", stub.received())
	}
	if !strings.Contains(err.Error(), "torn down on the controller") {
		t.Errorf("the error does not say which way round the divergence is, so an operator reading "+
			"it will retry a teardown that already happened: %v", err)
	}
}
