package access

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The ABAC row of docs/evidence/display-equals-enforcement.md at the access
// proxy, against the migrated schema: the policies, the subject's attributes,
// the route and the audit table are the real ones.
//
// The same three states as at the authorization endpoint
// (internal/oauth/abac_gate_testdb_test.go): enforce refuses the subject a deny
// policy names with a 403 and records access.abac.denied, observe lets it
// through and records access.abac.would_deny, and a subject no policy names
// passes in every mode and leaves no record.
func TestABACGateAtTheProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name, department string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, department, enabled)
			VALUES ($1::uuid, $2, $3, $4, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test", department).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}

	route := &ProxyRoute{Name: "payroll-" + suffix}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url)
		VALUES ($1::uuid, $2, 'https://payroll.example.test', 'http://payroll.internal:8080')
		RETURNING id::text`, org, route.Name).Scan(&route.ID); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	app := uuid.NewString()
	var policyID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO abac_policies (org_id, name, resource_type, resource_id, conditions, effect, priority, enabled)
		VALUES ($1::uuid, 'contractors off payroll', 'application', $2::uuid,
		        '[{"attribute":"department","operator":"eq","value":"Contractors"}]'::jsonb, 'deny', 10, true)
		RETURNING id::text`, org, app).Scan(&policyID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	logger := zap.NewNop()
	gate := func(mode, userID string) (bool, *httptest.ResponseRecorder) {
		t.Helper()
		s := &Service{
			db:           db,
			config:       &config.Config{ABACEnforce: mode},
			logger:       logger,
			auditService: NewUnifiedAuditService(db, logger),
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "https://payroll.example.test/", nil).
			WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
		return s.abacGateAllows(c, route, userID, org, app), w
	}
	// decisions returns every ABAC decision recorded for the user, as
	// "event_type policy_id route_id".
	decisions := func(userID string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `
			SELECT event_type, COALESCE(details->>'policy_id', ''), COALESCE(route_id::text, '')
			FROM unified_audit_events
			WHERE user_id = $1::uuid AND source = $2
			ORDER BY created_at`, userID, appaccess.SourceProxy)
		if err != nil {
			t.Fatalf("read decisions: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var eventType, policy, routeID string
			if err := rows.Scan(&eventType, &policy, &routeID); err != nil {
				t.Fatalf("scan decision: %v", err)
			}
			out = append(out, eventType+" "+policy+" "+routeID)
		}
		return out
	}

	// THE NEGATIVE HALF.
	t.Run("enforce refuses the subject a deny policy names, and records it", func(t *testing.T) {
		contractor := seedUser("abac-proxy-enforce", "Contractors")
		allowed, w := gate("enforce", contractor)
		if allowed || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "denied by policy") {
			t.Fatalf("got allowed=%v status=%d body=%s, want a 403 denied by policy", allowed, w.Code, w.Body.String())
		}
		want := appaccess.EventTypeABACDenied + " " + policyID + " " + route.ID
		if got := decisions(contractor); len(got) != 1 || got[0] != want {
			t.Fatalf("recorded %v, want exactly [%s]", got, want)
		}
	})

	// THE POSITIVE HALF.
	t.Run("enforce lets through a subject no policy names, and records nothing", func(t *testing.T) {
		engineer := seedUser("abac-proxy-engineer", "Engineering")
		allowed, w := gate("enforce", engineer)
		if !allowed || w.Body.Len() != 0 {
			t.Fatalf("got allowed=%v body=%s, want through with nothing written", allowed, w.Body.String())
		}
		if got := decisions(engineer); len(got) != 0 {
			t.Fatalf("recorded %v for a subject no policy names", got)
		}
	})

	// The staging states either side of enforce.
	t.Run("observe lets the named subject through and records what enforce would do", func(t *testing.T) {
		contractor := seedUser("abac-proxy-observe", "Contractors")
		allowed, w := gate("observe", contractor)
		if !allowed || w.Body.Len() != 0 {
			t.Fatalf("got allowed=%v body=%s, want through with nothing written", allowed, w.Body.String())
		}
		want := appaccess.EventTypeABACWouldDeny + " " + policyID + " " + route.ID
		if got := decisions(contractor); len(got) != 1 || got[0] != want {
			t.Fatalf("recorded %v, want exactly [%s]", got, want)
		}
	})
	t.Run("off consults nothing and records nothing", func(t *testing.T) {
		contractor := seedUser("abac-proxy-off", "Contractors")
		if allowed, _ := gate("off", contractor); !allowed {
			t.Fatal("off refused a request")
		}
		if got := decisions(contractor); len(got) != 0 {
			t.Fatalf("off recorded %v", got)
		}
	})
}
