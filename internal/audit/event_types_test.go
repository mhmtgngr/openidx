package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The filter offers what the trail holds, per tenant.
//
// It used to offer eight names copied from the EventType constants, six of
// which nothing writes: filtering by "configuration" or "system" returned an
// empty list, and an empty audit list reads as "nothing happened". This drives
// the endpoint against a real trail with the values the product actually
// writes, and against a second tenant's rows, because the one thing worse than
// an empty filter on this surface is one that names another tenant's activity.
func TestAuditEventTypesComeFromTheTrail(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	const (
		orgA = "00000000-0000-0000-0000-000000000010"
		orgB = "00000000-0000-0000-0000-0000000000b0"
		user = "77777777-0000-0000-0000-0000000000d1"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (audit types)', 'org-b-audit-types')
	      ON CONFLICT (id) DO NOTHING`, orgB)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'aet-u', 'aet-u@test.local', $2)`, user, orgA)

	event := func(org, eventType, action string) {
		t.Helper()
		exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_id, target_type, details, timestamp, created_at, org_id)
		      VALUES (gen_random_uuid(), $1, 'security', $2, 'success', $3, $3, 'user', '{}', NOW(), NOW(), $4)`,
			eventType, action, user, org)
	}
	// Values this product actually writes -- none of which the console could
	// filter for, because none of them was on its list.
	event(orgA, "identity", "user.updated")
	event(orgA, "identity", "user.deleted")
	event(orgA, "authentication", "login_failed")
	event(orgA, "pam.recording.sealed", "recording.seal")
	// Another tenant's trail.
	event(orgB, "provisioning", "scim.user.created")

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, logger: zap.NewNop()}
	router := gin.New()
	router.GET("/audit/event-types", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgA}))
		svc.handleEventTypes(c)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/audit/event-types", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("event-types returned %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		EventTypes []EventTypeCount `json:"event_types"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}

	got := map[string]int64{}
	for _, e := range body.EventTypes {
		got[e.Type] = e.Count
	}
	if got["identity"] != 2 {
		t.Errorf("identity count = %d, want 2; got %v", got["identity"], got)
	}
	for _, want := range []string{"authentication", "pam.recording.sealed"} {
		if got[want] == 0 {
			t.Errorf("%q is in this tenant's trail and the filter does not offer it; got %v", want, got)
		}
	}
	if _, ok := got["provisioning"]; ok {
		t.Errorf("the filter offers %q, which only the other tenant's trail contains", "provisioning")
	}
	// Ordering is by frequency, so the type an auditor is most likely to want is
	// near the top rather than alphabetically buried. Asserted as a property of
	// the response rather than by naming a winner: the migration chain itself
	// writes audit rows (authentication and system among them), so a fixture
	// this test seeds is not the whole trail -- which is the point of asking
	// the data instead of listing it.
	for i := 1; i < len(body.EventTypes); i++ {
		if body.EventTypes[i-1].Count < body.EventTypes[i].Count {
			t.Errorf("event types are not ordered by frequency: %q (%d) before %q (%d)",
				body.EventTypes[i-1].Type, body.EventTypes[i-1].Count,
				body.EventTypes[i].Type, body.EventTypes[i].Count)
			break
		}
	}
}
