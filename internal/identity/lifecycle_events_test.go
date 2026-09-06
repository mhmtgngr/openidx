package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/webhooks"
)

// recordingPublisher stands in for the webhook service and keeps what it was
// asked to send.
type recordingPublisher struct {
	mu     sync.Mutex
	events []publishedEvent
}

type publishedEvent struct {
	Type    string
	Payload map[string]interface{}
	OrgID   string
	HasOrg  bool
}

func (p *recordingPublisher) Publish(ctx context.Context, eventType string, payload interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ev := publishedEvent{Type: eventType}
	if m, ok := payload.(map[string]interface{}); ok {
		ev.Payload = m
	}
	if org, err := orgctx.From(ctx); err == nil {
		ev.OrgID, ev.HasOrg = org.ID, true
	}
	p.events = append(p.events, ev)
	return nil
}

// typesSent must be called with p.mu held: sync.Mutex is not reentrant, and the
// first draft of find() locked and then called a locking helper on the failure
// path. The test passed, and would have DEADLOCKED rather than reported the
// failure -- which the red-proof found by removing an emit and watching the run
// hang for sixty seconds instead of naming the missing event.
func (p *recordingPublisher) typesSentLocked() []string {
	var out []string
	for _, e := range p.events {
		out = append(out, e.Type)
	}
	return out
}

func (p *recordingPublisher) find(t *testing.T, eventType string) publishedEvent {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.events {
		if e.Type == eventType {
			return e
		}
	}
	t.Fatalf("%s was not published; sent: %v", eventType, p.typesSentLocked())
	return publishedEvent{}
}

// TestGroupLifecycleEventsReachTheWebhookService drives the four group handlers
// a router actually mounts and asserts the events come out.
//
// Until now they could not: every emitGroupLifecycleEvent call in the tree sat
// in internal/identity/handler.go, a second group CRUD implementation no router
// mounted. So group.created, group.updated, group.deleted, group.member_added
// and group.member_removed were offered on the webhook subscription form and
// published by nothing, on every install.
//
// group.member_removed is the one that matters most: it is the event a
// downstream system needs in order to REVOKE the access that came with the
// group. Its absence is a leaver who keeps their access.
func TestGroupLifecycleEventsReachTheWebhookService(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		org     = "00000000-0000-0000-0000-000000000010"
		admin   = "55555555-0000-0000-0000-0000000000a1"
		member  = "55555555-0000-0000-0000-0000000000a2"
		groupID = "55555555-0000-0000-0000-0000000000b1"
	)
	seedCtx := orgctx.WithBypassRLS(context.Background())
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, username, email, org_id) VALUES
	        ($1, 'wh-admin',  'wh-admin@test.local',  $3),
	        ($2, 'wh-member', 'wh-member@test.local', $3)`, admin, member, org)
	exec(`INSERT INTO groups (id, name, description, org_id) VALUES ($1, 'wh-group', 'seeded by the test', $2)`,
		groupID, org)

	pub := &recordingPublisher{}
	svc := NewService(db, nil, nil, zap.NewNop())
	svc.SetWebhookService(pub)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	router.PUT("/groups/:id", svc.handleUpdateGroup)
	router.POST("/groups/:id/members", svc.handleAddGroupMember)
	router.DELETE("/groups/:id/members/:userId", svc.handleRemoveGroupMember)
	router.DELETE("/groups/:id", svc.handleDeleteGroup)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}

	if w := do(http.MethodPut, "/groups/"+groupID, `{"name":"wh-group","description":"renamed"}`); w.Code != 200 {
		t.Fatalf("update group: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/groups/"+groupID+"/members", `{"user_id":"`+member+`"}`); w.Code != 200 {
		t.Fatalf("add member: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/groups/"+groupID+"/members/"+member, ""); w.Code != 200 {
		t.Fatalf("remove member: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/groups/"+groupID, ""); w.Code != 204 {
		t.Fatalf("delete group: %d %s", w.Code, w.Body.String())
	}

	for _, want := range []string{
		webhooks.EventGroupUpdated,
		webhooks.EventGroupMemberAdded,
		webhooks.EventGroupMemberRemoved,
		webhooks.EventGroupDeleted,
	} {
		ev := pub.find(t, want)
		if ev.Payload["group_id"] != groupID {
			t.Errorf("%s payload group_id = %v, want %s", want, ev.Payload["group_id"], groupID)
		}
		if ev.Payload["actor_id"] != admin {
			t.Errorf("%s payload actor_id = %v, want the acting admin", want, ev.Payload["actor_id"])
		}
		// The publish context is detached from the request but keeps the org:
		// webhook subscriptions are RLS-scoped, so an org-less publish sees no
		// subscriptions and delivers nothing, quietly, for every tenant.
		if !ev.HasOrg || ev.OrgID != org {
			t.Errorf("%s was published without the tenant (org=%q, present=%v); "+
				"RLS would have matched no subscriptions", want, ev.OrgID, ev.HasOrg)
		}
	}

	// Membership events name the member. A downstream system told only that
	// "a group changed" cannot grant or revoke anything.
	for _, want := range []string{webhooks.EventGroupMemberAdded, webhooks.EventGroupMemberRemoved} {
		if got := pub.find(t, want).Payload["user_id"]; got != member {
			t.Errorf("%s payload user_id = %v, want %s", want, got, member)
		}
	}
}
