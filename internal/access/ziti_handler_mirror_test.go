package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// DELETE /ziti/services/:id answered "ziti service deleted" over a record it
// had not deleted.
//
// The handler tears the service down on the controller, checks THAT, and then
// removes two rows: the BrowZer proxy_route pointing at the service, and the
// ziti_services row itself. Both used to discard their errors. So a database
// that refused them left the console listing a service the overlay no longer
// has, and a BrowZer route still publishing it -- with a 200 saying the
// deletion was done.
//
// 2dc69b3d fixed the handler and said plainly that it shipped without a test,
// because reaching the first line of the fix needs an authenticated management
// API. ziti_stub_test.go now provides one.

const zitiHandlerSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), from_url TEXT, to_url TEXT,
    ziti_enabled BOOLEAN DEFAULT false, ziti_service_name VARCHAR(255),
    browzer_enabled BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true, require_auth BOOLEAN DEFAULT true,
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), route_id UUID,
    enabled BOOLEAN DEFAULT true, org_id UUID);`

const (
	mirrorOrg = "00000000-0000-0000-0000-0000000000f1"
	mirrorSvc = "00000000-0000-0000-0000-0000000000f2"
)

// mirrorFixture seeds one Ziti service with a BrowZer route in front of it, and
// a controller that accepts the whole teardown.
func mirrorFixture(t *testing.T) (*Service, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: mirrorOrg})

	if _, err := db.Pool.Exec(ctx, zitiHandlerSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO ziti_services (id, ziti_id, name, org_id)
		  VALUES ($1::uuid, 'svc-1', 'a-service', $2::uuid)`, []any{mirrorSvc, mirrorOrg}},
		{`INSERT INTO proxy_routes (name, ziti_enabled, ziti_service_name, browzer_enabled, org_id)
		  VALUES ('browzer-a-service', true, 'a-service', true, $1::uuid)`, []any{mirrorOrg}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			cleanup()
			t.Fatalf("seed: %v", err)
		}
	}

	stub := newZitiStub(t)
	// TeardownZitiServiceByName looks each entity up by name filter and deletes
	// what it finds. An empty list is a controller with nothing left.
	stub.ok("GET /edge/management/v1/service-policies", `{"data":[]}`)
	stub.ok("GET /edge/management/v1/service-edge-router-policies", `{"data":[]}`)
	stub.ok("GET /edge/management/v1/configs", `{"data":[]}`)
	stub.ok("GET /edge/management/v1/services", `{"data":[{"id":"svc-1","name":"a-service"}]}`)
	stub.on("DELETE /edge/management/v1/services", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	svc := &Service{
		db:           db,
		logger:       zap.NewNop(),
		zitiProvider: newZitiProviderWith(zitiManagerAgainst(t, stub, db)),
	}
	return svc, stub, db, ctx, cleanup
}

func deleteZitiService(t *testing.T, s *Service, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/ziti/services/"+mirrorSvc, nil).WithContext(ctx)
	c.Params = gin.Params{{Key: "id", Value: mirrorSvc}}
	c.Set("roles", []string{"admin"})
	s.handleDeleteZitiService(c)
	return w
}

func TestDeletingAZitiServiceRemovesItFromBothSides(t *testing.T) {
	s, stub, db, ctx, cleanup := mirrorFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := deleteZitiService(t, s, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("deleting a ziti service answered %d: %s (controller saw %v)",
			w.Code, w.Body.String(), stub.received())
	}
	if !stub.saw("DELETE /edge/management/v1/services/svc-1") {
		t.Errorf("the service was not deleted on the controller; calls: %v", stub.received())
	}

	for _, q := range []struct{ what, sql string }{
		{"ziti_services row", `SELECT COUNT(*) FROM ziti_services WHERE id = $1::uuid`},
		{"BrowZer route", `SELECT COUNT(*) FROM proxy_routes WHERE ziti_service_name = 'a-service' AND $1::uuid IS NOT NULL`},
	} {
		var n int
		if err := db.Pool.QueryRow(ctx, q.sql, mirrorSvc).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", q.what, err)
		}
		if n != 0 {
			t.Errorf("the %s survives a successful delete", q.what)
		}
	}
}

// The case the old code answered 200 to: the overlay object is gone and the
// row is not.
func TestAZitiServiceDeleteThatKeepsItsRecordDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := mirrorFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_service_row_delete() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_service_row_delete_trg BEFORE DELETE ON ziti_services
		FOR EACH ROW EXECUTE FUNCTION refuse_service_row_delete();`); err != nil {
		t.Fatalf("install refusal trigger: %v", err)
	}

	w := deleteZitiService(t, s, ctx)
	if w.Code == http.StatusOK {
		t.Fatalf("the service was removed from the overlay, its record could not be deleted, and the "+
			"handler answered 200. The console goes on listing a service that does not exist: %s",
			w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "removed from the network") {
		t.Errorf("the response does not say which half succeeded, so an operator will read it as "+
			"\"nothing happened\" and retry a deletion that already ran: %s", w.Body.String())
	}

	// The controller half really did happen; without this the test would pass
	// on any early return.
	if !stub.saw("DELETE /edge/management/v1/services/svc-1") {
		t.Errorf("the service was never deleted on the controller, so this proves nothing about the "+
			"split; calls: %v", stub.received())
	}
}

// The BrowZer route is the other half, and it fails first — before the service
// row is touched — so it needs its own case.
func TestAZitiServiceDeleteThatKeepsItsBrowZerRouteDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := mirrorFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_route_delete() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_route_delete_trg BEFORE DELETE ON proxy_routes
		FOR EACH ROW EXECUTE FUNCTION refuse_route_delete();`); err != nil {
		t.Fatalf("install refusal trigger: %v", err)
	}

	w := deleteZitiService(t, s, ctx)
	if w.Code == http.StatusOK {
		t.Fatalf("the service is gone from the overlay and its BrowZer route still publishes it, and "+
			"the handler answered 200: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "BrowZer route") {
		t.Errorf("the response does not name the route left behind, which is the one thing an operator "+
			"has to go and remove: %s", w.Body.String())
	}
	if !stub.saw("DELETE /edge/management/v1/services/svc-1") {
		t.Errorf("the controller delete never happened; calls: %v", stub.received())
	}
}
