package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the per-route feature switches and the connectivity
// tests behind them, migration v162.
//
// A service_features row is the route's ZTNA switch: whether Ziti, BrowZer or
// Guacamole is on, the overlay service name it provisioned, and the health
// verdict the console shows beside it. A connection_tests row is the stored
// result of the "Test connection" button.
//
// THE SWITCH WAS GUARDED ON THE WAY ON AND OPEN ON THE WAY OFF. EnableFeature
// opens with validateRouteTypeCompatibility, which reads proxy_routes with
// `AND org_id = $2`, so enabling a feature on another organization's route
// already failed. DisableFeature had no route lookup anywhere in its path.
//
// THE TEST HISTORY IS INTERNAL TOPOLOGY: connection_tests.details carries the
// route's upstream URL, the host:port a probe dialled and the raw dial error.
func TestRouteFeatures_TenantIsolation(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('feat-b','feat-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	logger := zaptest.NewLogger(t)
	fm := NewFeatureManager(db, logger)
	// The reconciler owns controller-side Ziti mutations, so provisioning
	// writes the marker and never dials a controller. That is also what makes
	// the cross-tenant disable below reproducible without a Ziti manager.
	fm.SetReconcilerEnabled(true)
	s := &Service{db: db, logger: logger, featureManager: fm}

	ctxFor := func(org string) context.Context {
		return orgctx.With(context.Background(), orgctx.Org{ID: org})
	}

	seedRoute := func(org, name, upstream string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (name, from_url, to_url, org_id)
			VALUES ($1, $2, $3, $4::uuid) RETURNING id::text`,
			name+"-"+suffix, "/"+name+"-"+suffix, upstream, org).Scan(&id); err != nil {
			t.Fatalf("seed route %s: %v", name, err)
		}
		return id
	}

	// org A's route names an internal host. That string is what the leak below
	// would have handed to org B.
	const upstreamA = "http://payroll.internal.orga:8080"
	routeA := seedRoute(orgA, "feat-a", upstreamA)
	routeB := seedRoute(orgB, "feat-b", "http://svc.internal.orgb:9090")

	// org A turns Ziti on for its own route. This is the path that already
	// carried a tenant term; it must keep working.
	if err := fm.EnableFeature(ctxFor(orgA), routeA, FeatureZiti, &FeatureConfig{}, ""); err != nil {
		t.Fatalf("org A could not enable Ziti on its own route: %v", err)
	}

	featureState := func(routeID string) (enabled bool, health string) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, `
			SELECT COALESCE(enabled,false), COALESCE(health_status,'')
			FROM service_features WHERE route_id = $1::uuid AND feature_name = 'ziti'`,
			routeID).Scan(&enabled, &health); err != nil {
			t.Fatalf("read feature state: %v", err)
		}
		return
	}

	t.Run("the switch is guarded on the way off, not only on the way on", func(t *testing.T) {
		if err := fm.EnableFeature(ctxFor(orgB), routeA, FeatureZiti, &FeatureConfig{}, ""); err == nil {
			t.Error("org B enabled a feature on org A's route")
		}

		err := fm.DisableFeature(ctxFor(orgB), routeA, FeatureZiti)
		if err == nil {
			t.Error("org B disabled the ZTNA overlay on org A's route. DisableFeature had " +
				"no route lookup anywhere in its path: getDependentFeatures, " +
				"getFeature, deprovisionFeature and the UPDATE that follows all " +
				"addressed the row by route id alone")
		}

		enabled, _ := featureState(routeA)
		if !enabled {
			t.Error("org A's ziti feature row is now disabled")
		}
		// The half that made it silent: syncRouteFlags IS org-scoped, so it
		// matched no row and left the console reporting the route as
		// Ziti-protected while the feature row said otherwise.
		var zitiEnabled bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(ziti_enabled,false) FROM proxy_routes WHERE id = $1::uuid`,
			routeA).Scan(&zitiEnabled); err != nil {
			t.Fatalf("read route flags: %v", err)
		}
		if !zitiEnabled {
			t.Error("org A's route lost its ziti_enabled flag")
		}

		// The owner can still turn it off: the term must scope, not deny.
		if err := fm.DisableFeature(ctxFor(orgA), routeA, FeatureZiti); err != nil {
			t.Fatalf("org A could not disable its own feature: %v", err)
		}
		if enabled, _ := featureState(routeA); enabled {
			t.Error("org A's own disable did not take effect")
		}
		// Put it back for the health case below.
		if err := fm.EnableFeature(ctxFor(orgA), routeA, FeatureZiti, &FeatureConfig{}, ""); err != nil {
			t.Fatalf("re-enable: %v", err)
		}
	})

	t.Run("another tenant's feature status is not readable", func(t *testing.T) {
		if _, err := fm.GetServiceStatus(ctxFor(orgB), routeA); err == nil {
			t.Error("org B read the feature status of org A's route")
		}
		st, err := fm.GetServiceStatus(ctxFor(orgA), routeA)
		if err != nil {
			t.Fatalf("org A lost its own feature status: %v", err)
		}
		if st.Features[FeatureZiti] == nil {
			t.Error("org A's own ziti feature is missing from its service status")
		}
	})

	// entity of the leak: `details` is the whole per-test result map.
	t.Run("a route's test history is not another tenant's internal topology", func(t *testing.T) {
		seedTest := func(routeID, org, upstream string) {
			t.Helper()
			details := fmt.Sprintf(`{"upstream":{"success":true,"details":{"url":%q}},
				"tcp":{"success":false,"error_message":"dial tcp %s: connect: connection refused"}}`,
				upstream, strings.TrimPrefix(upstream, "http://"))
			if _, err := db.Pool.Exec(ctx, `
				INSERT INTO connection_tests (route_id, org_id, test_type, success, latency_ms, details)
				VALUES ($1::uuid, $2::uuid, 'full', false, 12, $3::jsonb)`,
				routeID, org, details); err != nil {
				t.Fatalf("seed connection test: %v", err)
			}
		}
		seedTest(routeA, orgA, upstreamA)
		seedTest(routeB, orgB, "http://svc.internal.orgb:9090")

		history := func(org, routeID string) (int, string) {
			t.Helper()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/services/"+routeID+"/test-history", nil).
				WithContext(ctxFor(org))
			c.Params = gin.Params{{Key: "id", Value: routeID}}
			s.handleGetConnectionTestHistory(c)
			var out struct {
				Total int `json:"total"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			return out.Total, w.Body.String()
		}

		total, body := history(orgB, routeA)
		if total != 0 {
			t.Errorf("org B read %d of org A's connection tests", total)
		}
		if strings.Contains(body, "payroll.internal.orga") {
			t.Errorf("org B was handed org A's internal hostname: %s. The read was "+
				"`FROM connection_tests WHERE route_id = $1` with no organization "+
				"and no check that the route belonged to the caller, and details "+
				"carries the upstream URL, the host:port a probe dialled and the "+
				"raw dial error", body)
		}

		total, body = history(orgA, routeA)
		if total != 1 {
			t.Errorf("org A sees %d of its own tests, want 1: %s", total, body)
		}
		if !strings.Contains(body, "payroll.internal.orga") {
			t.Error("org A lost the details of its own connection test")
		}
	})

	// The health verdict was being measured and thrown away.
	t.Run("a connection test moves the health badge it was already measuring", func(t *testing.T) {
		if _, health := featureState(routeA); health != string(HealthStatusUnknown) {
			t.Fatalf("precondition: ziti health is %q, want unknown", health)
		}

		s.recordFeatureHealth(ctxFor(orgA), routeA, &ConnectionTestResult{
			Tests: map[string]*TestResult{
				"ziti": {Success: false, ErrorMessage: "Service not found: openidx-feat-a"},
			},
		})

		_, health := featureState(routeA)
		if health != string(HealthStatusUnhealthy) {
			t.Errorf("after a failed Ziti probe the feature health is %q, want unhealthy. "+
				"UpdateFeatureHealth is the only writer of this column in the tree "+
				"and had no caller, so the dot on the Zero Trust page and the badge "+
				"on the route's feature panel could only ever read 'unknown'", health)
		}
		var checked *time.Time
		if err := db.Pool.QueryRow(ctx,
			`SELECT last_health_check FROM service_features WHERE route_id = $1::uuid AND feature_name = 'ziti'`,
			routeA).Scan(&checked); err != nil {
			t.Fatalf("read last_health_check: %v", err)
		}
		if checked == nil {
			t.Error("the health verdict was recorded with no time on it")
		}

		// And it cannot be written across tenants.
		if err := fm.UpdateFeatureHealth(ctxFor(orgB), routeA, FeatureZiti,
			HealthStatusHealthy, ""); err == nil {
			t.Error("org B wrote a health verdict onto org A's route")
		}
		if _, health := featureState(routeA); health != string(HealthStatusUnhealthy) {
			t.Errorf("org A's health verdict was overwritten to %q", health)
		}

		// A probe that did not run leaves the verdict alone: "not measured this
		// time" is not a verdict, and 'unknown' would be worse than the truth.
		s.recordFeatureHealth(ctxFor(orgA), routeA, &ConnectionTestResult{
			Tests: map[string]*TestResult{"upstream": {Success: true}},
		})
		if _, health := featureState(routeA); health != string(HealthStatusUnhealthy) {
			t.Errorf("an upstream-only test reset the ziti verdict to %q", health)
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal", func(t *testing.T) {
		for name, handler := range map[string]gin.HandlerFunc{
			"test-connection": s.handleTestConnection,
			"test-history":    s.handleGetConnectionTestHistory,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/services/"+routeA+"/test-history", nil) // bare context
			c.Params = gin.Params{{Key: "id", Value: routeA}}
			handler(c)
			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}

		// getRouteByID drops its tenant filter when the context carries no
		// organization, which is right for the data plane and wrong for a
		// request — so the handler requires one rather than inheriting that.
		for _, fn := range []func(context.Context, string, FeatureName) error{
			func(c context.Context, r string, f FeatureName) error { return fm.DisableFeature(c, r, f) },
			func(c context.Context, r string, f FeatureName) error {
				return fm.EnableFeature(c, r, f, &FeatureConfig{}, "")
			},
		} {
			if err := fn(context.Background(), routeA, FeatureZiti); err == nil {
				t.Error("a feature toggle with no organization on the context succeeded")
			}
		}
	})
}
