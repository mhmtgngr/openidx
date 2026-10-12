package access

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// recordUnifiedEvent, on the migrated schema: an administrator's event lands
// in the request's tenant with the administrator as actor, the other tenant's
// trail carries none of it, and its administrator's query does not see it.
// (This was the revocation half of the retired temporary access links' audit
// test; the legal-hold events are what ride the helper now.)
func TestAUnifiedEventLandsInItsTenantOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "unified-event-b-"+suffix).
		Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	var admin string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, enabled, org_id)
		VALUES ($1::varchar, $1::varchar || '@example.test', true, $2::uuid) RETURNING id::text`,
		"ue-admin-"+suffix, orgA).Scan(&admin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	logger := zap.NewNop()
	svc := &Service{db: db, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
	sessionID := "11111111-2222-3333-4444-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1e12)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/guacamole/sessions/"+sessionID+"/legal-hold", nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
	c.Set("user_id", admin)
	c.Set("roles", []string{"admin"})
	svc.recordUnifiedEvent(c, "", "guacamole.legal_hold_placed", admin, sessionID, "guacamole_session",
		map[string]interface{}{"session_id": sessionID, "reason": "litigation"})

	var n int
	var actor *string
	if err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), MAX(user_id::text) FROM unified_audit_events
		 WHERE event_type = 'guacamole.legal_hold_placed' AND details->>'session_id' = $1 AND org_id = $2`,
		sessionID, orgA).Scan(&n, &actor); err != nil {
		t.Fatalf("read events: %v", err)
	}
	if n != 1 || actor == nil || *actor != admin {
		t.Errorf("org A has %d event row(s) with actor %v, want one with the administrator", n, actor)
	}
	if err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM unified_audit_events WHERE details->>'session_id' = $1 AND org_id = $2`,
		sessionID, orgB).Scan(&n); err != nil {
		t.Fatalf("count org B events: %v", err)
	}
	if n != 0 {
		t.Errorf("org B's trail carries %d of org A's events", n)
	}
	res, err := svc.auditService.QueryEvents(orgctx.With(ctx, orgctx.Org{ID: orgB}),
		&AuditQueryFilters{EventTypes: []string{"guacamole.legal_hold_placed"}, Limit: 50})
	if err != nil {
		t.Fatalf("query as org B: %v", err)
	}
	for _, e := range res.Events {
		if fmt.Sprint(e.Details["session_id"]) == sessionID {
			t.Errorf("org B's administrator sees org A's event")
		}
	}
	res, err = svc.auditService.QueryEvents(orgctx.With(ctx, orgctx.Org{ID: orgA}),
		&AuditQueryFilters{EventTypes: []string{"guacamole.legal_hold_placed"}, Limit: 50})
	if err != nil {
		t.Fatalf("query as org A: %v", err)
	}
	if len(res.Events) == 0 {
		t.Error("org A's administrator does not see the event on the Unified Audit query")
	}
}
