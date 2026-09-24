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

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/portal"
)

// The JIT elevation row of docs/evidence/display-equals-enforcement.md, run in
// the order the row gives: grant a time-boxed role, confirm the admin's User
// Access 360 lists it and the user's portal dashboard counts it, press the kill
// switch, then check that the role is gone, the request is expired and the
// response reports one elevation ended.
//
// Each step had a test of its own (TestUserAccessMap_CrossPillar,
// TestGetAccessOverview_CrossPillar, TestKillSwitch_SeversAllPillars), but on
// tables the tests wrote by hand and never in sequence, and the kill-switch
// test read neither the request's status nor pam_jit_grants_revoked. This one
// runs on the migrated schema, through the two admin routes as they are
// mounted, and the grant is the shape the approval workflow writes: a
// fulfilled access_requests row with an expiry plus the user_roles row it made.
func TestJITElevationEndsAtTheKillSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	target := seedUser("jit-target")
	bystander := seedUser("jit-bystander")
	admin := seedUser("jit-admin")

	roleName := "break-glass-" + suffix
	var roleID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, roleName).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	// grant writes what an approved, time-boxed role request leaves behind.
	grant := func(userID string) string {
		t.Helper()
		var requestID string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO access_requests (requester_id, org_id, resource_type, resource_id, resource_name, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'role', $3::uuid, $4, 'fulfilled', NOW() + INTERVAL '2 hours')
			RETURNING id::text`, userID, org, roleID, roleName).Scan(&requestID); err != nil {
			t.Fatalf("seed elevation request: %v", err)
		}
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
			userID, roleID, org); err != nil {
			t.Fatalf("seed role assignment: %v", err)
		}
		return requestID
	}
	targetRequest := grant(target)
	bystanderRequest := grant(bystander)

	logger := zap.NewNop()
	svc := &Service{db: db, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Next()
	})
	router.GET("/api/v1/access/users/:id/access-map", svc.handleUserAccessMap)
	router.POST("/api/v1/access/users/:id/kill-switch", svc.handleUserKillSwitch)

	// listed is what User Access 360 shows for the user: the elevations and
	// whether the role is among the roles they hold.
	listed := func(userID string) (elevations []AccessMapJITGrant, holdsRole bool) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/access/users/"+userID+"/access-map", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("access map for %s: %d %s", userID, w.Code, w.Body.String())
		}
		var m UserAccessMap
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode access map: %v", err)
		}
		for _, r := range m.IAM.Roles {
			if r.ID == roleID {
				holdsRole = true
			}
		}
		return m.PAM.ActiveJITGrants, holdsRole
	}
	// counted is the "active JIT grants" figure on the user's own dashboard.
	counted := func(userID string) int {
		t.Helper()
		ov, err := portal.NewService(db, logger).GetAccessOverview(orgCtx, userID)
		if err != nil {
			t.Fatalf("portal overview for %s: %v", userID, err)
		}
		return ov.Privileged.ActiveJITGrants
	}
	status := func(requestID string) string {
		t.Helper()
		var s string
		if err := db.Pool.QueryRow(ctx,
			`SELECT status FROM access_requests WHERE id = $1::uuid`, requestID).Scan(&s); err != nil {
			t.Fatalf("read request %s: %v", requestID, err)
		}
		return s
	}
	assigned := func(userID string) bool {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
			userID, roleID).Scan(&n); err != nil {
			t.Fatalf("read role assignment: %v", err)
		}
		return n > 0
	}

	// Granted: listed, counted and held.
	elevations, holds := listed(target)
	if len(elevations) != 1 || elevations[0].ID != targetRequest || elevations[0].RoleName != roleName {
		t.Fatalf("User Access 360 must list the one elevation %s (%s), got %+v", targetRequest, roleName, elevations)
	}
	if !holds {
		t.Fatalf("User Access 360 must show the elevated role among the user's roles")
	}
	if got := counted(target); got != 1 {
		t.Fatalf("the portal dashboard must count 1 active elevation, got %d", got)
	}

	// The kill switch.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/access/users/"+target+"/kill-switch",
		strings.NewReader(`{"reason":"evidence run"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("kill switch: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		JITGrantsRevoked *int64 `json:"pam_jit_grants_revoked"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode kill-switch response: %v", err)
	}
	if result.JITGrantsRevoked == nil || *result.JITGrantsRevoked != 1 {
		t.Errorf("pam_jit_grants_revoked must be 1 (0 reads as \"held none\"), got %s", w.Body.String())
	}

	// Ended: the role is gone, the request is expired, and neither view shows it.
	if assigned(target) {
		t.Errorf("the elevated role must be gone after the kill switch")
	}
	if got := status(targetRequest); got != "expired" {
		t.Errorf("the elevation request must be expired, got %q", got)
	}
	elevations, holds = listed(target)
	if len(elevations) != 0 || holds {
		t.Errorf("User Access 360 must show no elevation and no role after the kill switch, got %+v (holds role: %v)", elevations, holds)
	}
	if got := counted(target); got != 0 {
		t.Errorf("the portal dashboard must count 0 after the kill switch, got %d", got)
	}
	var audited string
	if err := db.Pool.QueryRow(ctx, `
		SELECT COALESCE(details->>'pam_jit_grants_revoked', '')
		  FROM unified_audit_events
		 WHERE event_type = 'user.kill_switch' AND user_id = $1::uuid`, target).Scan(&audited); err != nil {
		t.Fatalf("read kill-switch audit event: %v", err)
	}
	if audited != "1" {
		t.Errorf("the audit event must record 1 elevation ended, got %q", audited)
	}

	// Scoped to the user: someone else holding the same role through the same
	// workflow keeps it.
	if !assigned(bystander) || status(bystanderRequest) != "fulfilled" || counted(bystander) != 1 {
		t.Errorf("another user's elevation must survive: assigned=%v status=%q counted=%d",
			assigned(bystander), status(bystanderRequest), counted(bystander))
	}
}
