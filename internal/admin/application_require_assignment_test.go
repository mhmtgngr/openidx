package admin

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// requireAssignmentOf reads the raw column for an application id, bypassing the
// service so the assertions test the DB state rather than the read path.
func requireAssignmentOf(t *testing.T, s *Service, appID string) bool {
	t.Helper()
	var v bool
	if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT require_assignment FROM applications WHERE id = $1`, appID).Scan(&v); err != nil {
		t.Fatalf("read require_assignment for %s: %v", appID, err)
	}
	return v
}

// TestUpdateApplicationRequireAssignment covers the whole reason the column
// needs an admin-API path: without one, the OIDC assignment gate
// (oauth.assignmentGateAllows) was reachable only by manual SQL. It asserts the
// three properties that make the control safe to expose — it persists, it is
// org-scoped like every other field of the allowlisted updater, and it is never
// disturbed by an edit that does not name it.
func TestUpdateApplicationRequireAssignment(t *testing.T) {
	db, cleanup := setupPAMTestDB(t) // skips if no container runtime
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		orgA  = "00000000-0000-0000-0000-0000000000a1"
		orgB  = "00000000-0000-0000-0000-0000000000b1"
		appA  = "11111111-0000-0000-0000-0000000000a1"
		appB  = "11111111-0000-0000-0000-0000000000b1"
		appA2 = "11111111-0000-0000-0000-0000000000a2"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org A (ra)', 'org-a-ra')`, orgA)
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (ra)', 'org-b-ra')`, orgB)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id)
		VALUES ($1, 'ra-client-a', 'Grafana', 'web', true, $2)`, appA, orgA)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id)
		VALUES ($1, 'ra-client-b', 'Other Tenant App', 'web', true, $2)`, appB, orgB)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id)
		VALUES ($1, 'ra-client-a2', 'Already Gated', 'web', true, $2)`, appA2, orgA)

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	// Default from migration v137: off, so the gate is inert until an admin acts.
	if requireAssignmentOf(t, s, appA) {
		t.Fatalf("require_assignment defaulted to true; it must default false")
	}

	// 1. Turning it on persists.
	if err := s.UpdateApplication(ctxA, appA, map[string]interface{}{"require_assignment": true}); err != nil {
		t.Fatalf("UpdateApplication(require_assignment=true): %v", err)
	}
	if !requireAssignmentOf(t, s, appA) {
		t.Errorf("require_assignment did not persist as true")
	}

	// ...and turning it back off persists too (the control must be reversible).
	if err := s.UpdateApplication(ctxA, appA, map[string]interface{}{"require_assignment": false}); err != nil {
		t.Fatalf("UpdateApplication(require_assignment=false): %v", err)
	}
	if requireAssignmentOf(t, s, appA) {
		t.Errorf("require_assignment stayed true after being set back to false")
	}

	// 2. Org scoping: org A cannot flip org B's application. The updater is
	// scoped by `WHERE id = $N AND org_id = $N+1`, so this must be a no-op —
	// with 17 non-default orgs on the deployment, losing that would be a
	// cross-tenant lockout primitive.
	if err := s.UpdateApplication(ctxA, appB, map[string]interface{}{"require_assignment": true}); err != nil {
		t.Fatalf("cross-org UpdateApplication returned an error: %v", err)
	}
	if requireAssignmentOf(t, s, appB) {
		t.Errorf("org A flipped require_assignment on org B's application — org scoping lost")
	}

	// 3. Updating another field leaves require_assignment untouched: an admin
	// renaming an application must not silently disable its sign-in gate.
	exec(`UPDATE applications SET require_assignment = true WHERE id = $1`, appA2)
	if err := s.UpdateApplication(ctxA, appA2, map[string]interface{}{"name": "Renamed"}); err != nil {
		t.Fatalf("UpdateApplication(name): %v", err)
	}
	if !requireAssignmentOf(t, s, appA2) {
		t.Errorf("a name-only update cleared require_assignment")
	}
	var name string
	if err := db.Pool.QueryRow(seedCtx, `SELECT name FROM applications WHERE id = $1`, appA2).Scan(&name); err != nil {
		t.Fatalf("read name: %v", err)
	}
	if name != "Renamed" {
		t.Errorf("name = %q, want %q", name, "Renamed")
	}
}

// TestApplicationReadPathsReturnRequireAssignment proves the console can render
// the control's current state: both the list that feeds the applications page
// and the single-application detail handler carry the column.
func TestApplicationReadPathsReturnRequireAssignment(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		orgID   = "00000000-0000-0000-0000-0000000000c1"
		gatedID = "11111111-0000-0000-0000-0000000000c1"
		openID  = "11111111-0000-0000-0000-0000000000c2"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org C (ra)', 'org-c-ra')`, orgID)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, require_assignment, org_id)
		VALUES ($1, 'ra-client-gated', 'Gated App', 'web', true, true, $2)`, gatedID, orgID)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, require_assignment, org_id)
		VALUES ($1, 'ra-client-open', 'Open App', 'web', true, false, $2)`, openID, orgID)

	s := &Service{db: db, logger: zap.NewNop()}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	apps, _, err := s.ListApplications(ctx, 0, 100)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	seen := map[string]bool{}
	for _, a := range apps {
		seen[a.ID] = a.RequireAssignment
	}
	if !seen[gatedID] {
		t.Errorf("list did not report require_assignment=true for the gated application")
	}
	if seen[openID] {
		t.Errorf("list reported require_assignment=true for an ungated application")
	}

	// The JSON must carry the field even when false — the console needs to tell
	// "off" from "this build does not have the field".
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: openID}}
	c.Request = httptest.NewRequest("GET", "/api/v1/applications/"+openID, nil).WithContext(ctx)
	s.handleGetApplication(c)
	if w.Code != 200 {
		t.Fatalf("handleGetApplication: status = %d, body = %s", w.Code, w.Body.String())
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	v, ok := raw["require_assignment"]
	if !ok {
		t.Fatalf("detail response omits require_assignment: %s", w.Body.String())
	}
	if v != false {
		t.Errorf("require_assignment = %v, want false", v)
	}
}
