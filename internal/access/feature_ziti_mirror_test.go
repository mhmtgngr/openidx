package access

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Turning Ziti on for a route: the service is real, the route does not use it.
//
// provisionFeature creates the Ziti service, its Bind and Dial policies and its
// service-edge-router policy on the controller, and then writes one row --
// proxy_routes.ziti_service_name -- which is the only thing that makes the
// route actually use any of it. That write used to be unchecked.
//
// Losing it is the quiet direction of this class. Nothing breaks: the route
// keeps serving over plain HTTP exactly as before, so no request fails and no
// alarm goes off. What is gone is the zero-trust property the operator just
// switched on, and the console reports the feature as provisioned because the
// controller half succeeded.

const featureZitiSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), to_url TEXT,
    remote_host VARCHAR(255), remote_port INTEGER,
    ziti_enabled BOOLEAN DEFAULT false, ziti_service_name VARCHAR(255),
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), protocol VARCHAR(16),
    host VARCHAR(255), port INTEGER, enabled BOOLEAN DEFAULT true, org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE, name VARCHAR(255), policy_type VARCHAR(16),
    service_roles JSONB DEFAULT '[]', identity_roles JSONB DEFAULT '[]',
    is_system BOOLEAN DEFAULT false, org_id UUID);`

const (
	featureOrg   = "00000000-0000-0000-0000-0000000000c1"
	featureRoute = "00000000-0000-0000-0000-0000000000c2"
)

// featureZitiFixture gives a FeatureManager whose controller accepts the whole
// provisioning sequence, with the reconciler off so the imperative path runs.
func featureZitiFixture(t *testing.T) (*FeatureManager, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: featureOrg})

	if _, err := db.Pool.Exec(ctx, featureZitiSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (id, name, to_url, remote_host, remote_port, org_id)
		 VALUES ($1::uuid, 'payroll', 'http://payroll.internal:8080', 'payroll.internal', 8080, $2::uuid)`,
		featureRoute, featureOrg); err != nil {
		cleanup()
		t.Fatalf("seed the route: %v", err)
	}

	stub := newZitiStub(t)
	stub.on("POST /edge/management/v1/services", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"svc-new"}}`))
	})
	stub.on("POST /edge/management/v1/service-policies", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"pol-new"}}`))
	})
	stub.on("POST /edge/management/v1/service-edge-router-policies", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"serp-new"}}`))
	})

	zm := zitiManagerAgainst(t, stub, db)
	zm.initialized = true // provisionFeature refuses an uninitialised manager

	fm := &FeatureManager{db: db, logger: zap.NewNop(), zitiProvider: newZitiProviderWith(zm)}
	return fm, stub, db, ctx, cleanup
}

func TestEnablingZitiOnARoutePointsTheRouteAtTheService(t *testing.T) {
	fm, stub, db, ctx, cleanup := featureZitiFixture(t)
	if fm == nil {
		return
	}
	defer cleanup()

	ids, err := fm.provisionFeature(ctx, featureRoute, featureOrg, FeatureZiti, &FeatureConfig{})
	if err != nil {
		t.Fatalf("provisioning Ziti answered %v (controller saw %v)", err, stub.received())
	}
	if ids["ziti_service_name"] != "openidx-payroll" {
		t.Errorf("provisioning reported service name %q", ids["ziti_service_name"])
	}

	var enabled bool
	var name *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_enabled, ziti_service_name FROM proxy_routes WHERE id = $1::uuid`,
		featureRoute).Scan(&enabled, &name); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if !enabled || name == nil || *name != "openidx-payroll" {
		t.Errorf("after a successful provision the route is ziti_enabled=%v service=%v; it is still "+
			"serving without the overlay", enabled, name)
	}
}

// The case the old code returned success from: the service exists on the
// overlay, and nothing points at it.
func TestAZitiEnableThatCannotPointTheRouteAtTheServiceDoesNotReportSuccess(t *testing.T) {
	fm, stub, db, ctx, cleanup := featureZitiFixture(t)
	if fm == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "proxy_routes", "UPDATE")

	_, err := fm.provisionFeature(ctx, featureRoute, featureOrg, FeatureZiti, &FeatureConfig{})
	if err == nil {
		t.Fatal("the ziti service was created on the controller, the route was not pointed at it, and " +
			"provisioning reported success. The route serves over plain HTTP and the console shows the " +
			"feature as provisioned")
	}
	if !strings.Contains(err.Error(), "serving without the overlay") {
		t.Errorf("the error does not say the route is still serving without the overlay, which is the "+
			"one thing that looks like nothing happening: %v", err)
	}
	// The controller half really did happen — otherwise this passes on any
	// earlier failure and says nothing about the split.
	if !stub.saw("POST /edge/management/v1/services") {
		t.Errorf("no service was created on the controller; calls: %v", stub.received())
	}

	var enabled bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_enabled FROM proxy_routes WHERE id = $1::uuid`, featureRoute).Scan(&enabled); err != nil {
		t.Fatalf("read the route back: %v", err)
	}
	if enabled {
		t.Error("the route was updated; the test's premise (the write was refused) did not hold")
	}
}
