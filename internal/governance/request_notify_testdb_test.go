package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// publishedEvent is one webhook event, with the tenancy of the context it was
// published under.
type publishedEvent struct {
	Type    string
	Org     string
	Bypass  bool
	Payload map[string]interface{}
}

// fakePublisher stands in for internal/webhooks and keeps what it was given.
type fakePublisher struct {
	mu     sync.Mutex
	events []publishedEvent
}

func (f *fakePublisher) Publish(ctx context.Context, eventType string, payload interface{}) error {
	org, _ := orgctx.From(ctx)
	p, _ := payload.(map[string]interface{})
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, publishedEvent{Type: eventType, Org: org.ID, Bypass: orgctx.IsBypassRLS(ctx), Payload: p})
	return nil
}

// of returns the events of one type about one request.
func (f *fakePublisher) of(eventType, requestID string) []publishedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []publishedEvent
	for _, e := range f.events {
		if e.Type == eventType && e.Payload["request_id"] == requestID {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakePublisher) all() []publishedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]publishedEvent(nil), f.events...)
}

// Section 6.10 of the third-party access framework: an access request tells
// the people it concerns, and the tenant's SIEM, what happens to it. On the
// migrated schema, through the real handlers and sweeps:
//
//   - filing a request tells its first step's approvers, and only them, and
//     publishes access_request.created;
//   - a satisfied step tells the next step's approvers;
//   - the last approval tells the requester the access is theirs, and
//     publishes access_request.approved with the window;
//   - the requester is warned, once, when the access ends within the hour
//     (access_request.expiring), and told when it ended (access_request.ended);
//   - a denial and a request nobody answered in time are told and published
//     too;
//   - a requester who switched those notifications off is not told, and the
//     events are published all the same;
//   - every event is published under the request's own organization and no
//     row-level-security bypass, the sweeps' included.
func TestAccessRequestsTellTheirApproversAndRequester(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	sweep := orgctx.WithBypassRLS(bg)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	requester, first, second := user("rn-requester"), user("rn-first"), user("rn-second")
	entry := func(name string) string {
		id := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
			VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, name+"-"+suffix)
		exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view}')`, org, id, requester)
		return id
	}
	twoSteps, oneStep, unanswered, quiet := entry("rn-two"), entry("rn-one"), entry("rn-wait"), entry("rn-quiet")
	// Two steps on one entry; every other entry is the first approver's alone.
	exec(`INSERT INTO approval_policies (org_id, name, resource_type, resource_id, approval_steps, enabled)
		VALUES ($1, $2, 'pam_entry', $3, $4::jsonb, true)`, org, "rn-two-"+suffix, twoSteps,
		fmt.Sprintf(`[{"type":"specific_user","approver_id":%q},{"type":"specific_user","approver_id":%q}]`, first, second))
	exec(`INSERT INTO approval_policies (org_id, name, resource_type, approval_steps, enabled)
		VALUES ($1, $2, 'pam_entry', $3::jsonb, true)`, org, "rn-one-"+suffix,
		fmt.Sprintf(`[{"type":"specific_user","approver_id":%q}]`, first))

	pub := &fakePublisher{}
	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop(), webhooks: pub}
	call := func(userID, path, body string) (int, map[string]interface{}) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{"user"})
			c.Next()
		})
		r.POST("/requests", s.handleCreateAccessRequest)
		r.POST("/requests/:id/approve", s.handleApproveRequest)
		r.POST("/requests/:id/deny", s.handleDenyRequest)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	file := func(entryID string) string {
		t.Helper()
		code, body := call(requester, "/requests", fmt.Sprintf(
			`{"resource_type":"pam_entry","resource_id":%q,"justification":"patch window","duration":"4h"}`, entryID))
		if code != http.StatusCreated {
			t.Fatalf("file a request for %s: %d %v", entryID, code, body)
		}
		return scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid AND status = 'pending'`,
			requester, entryID)
	}
	// told counts the notifications of a type a user holds about a request,
	// and of a kind when one is given.
	told := func(userID, notifType, requestID, kind string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications
			 WHERE user_id = $1 AND type = $2 AND metadata->>'request_id' = $3 AND ($4 = '' OR metadata->>'kind' = $4)`,
			userID, notifType, requestID, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Filed: the first step's approver is told, and nobody else.
	request := file(twoSteps)
	if n := told(first, "approval_pending", request, ""); n != 1 {
		t.Errorf("the first step's approver holds %d approval_pending notifications, want 1", n)
	}
	if n := told(second, "approval_pending", request, ""); n != 0 {
		t.Errorf("the second step's approver was told before their step: %d notifications", n)
	}
	if n := told(requester, "request_update", request, ""); n != 0 {
		t.Errorf("the requester was told something on filing: %d notifications", n)
	}
	if n := len(pub.of("access_request.created", request)); n != 1 {
		t.Errorf("access_request.created published %d times, want 1", n)
	}

	// The first step is satisfied: the second step's approver is told.
	if code, body := call(first, "/requests/"+request+"/approve", `{"comments":"ok"}`); code != http.StatusOK || body["status"] != "pending" {
		t.Fatalf("the first approver approves: %d %v, want 200 pending", code, body)
	}
	if n := told(second, "approval_pending", request, ""); n != 1 {
		t.Errorf("the second step's approver holds %d approval_pending notifications after the first step, want 1", n)
	}
	if n := told(first, "approval_pending", request, ""); n != 1 {
		t.Errorf("the first approver was told again: %d notifications", n)
	}
	if n := len(pub.of("access_request.approved", request)); n != 0 {
		t.Errorf("access_request.approved published before the last step")
	}

	// The last step: the requester is told the access is theirs.
	if code, body := call(second, "/requests/"+request+"/approve", `{"comments":"ok"}`); code != http.StatusOK || body["status"] != "fulfilled" {
		t.Fatalf("the second approver approves: %d %v, want 200 fulfilled", code, body)
	}
	if n := told(requester, "request_update", request, "approved"); n != 1 {
		t.Errorf("the requester holds %d approved notifications, want 1", n)
	}
	if got := pub.of("access_request.approved", request); len(got) != 1 {
		t.Errorf("access_request.approved published %d times, want 1", len(got))
	} else if got[0].Payload["expires_at"] == nil || got[0].Payload["status"] != "fulfilled" {
		t.Errorf("access_request.approved carries %v, want the window and status fulfilled", got[0].Payload)
	}

	// Hours left: not warned yet.
	s.warnEndingAccess(sweep)
	if n := told(requester, "request_update", request, "expiring"); n != 0 {
		t.Errorf("the requester was warned with hours of access left: %d notifications", n)
	}

	// Ending within the hour: warned once, however many ticks see it.
	exec(`UPDATE access_requests SET expires_at = NOW() + INTERVAL '30 minutes' WHERE id = $1`, request)
	s.warnEndingAccess(sweep)
	s.warnEndingAccess(sweep)
	if n := told(requester, "request_update", request, "expiring"); n != 1 {
		t.Errorf("the requester holds %d expiring notifications after two ticks, want 1", n)
	}
	if n := len(pub.of("access_request.expiring", request)); n != 1 {
		t.Errorf("access_request.expiring published %d times after two ticks, want 1", n)
	}

	// The window ends: the access goes, and the requester is told.
	exec(`UPDATE access_requests SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, request)
	s.revokeExpiredJITAccess(sweep)
	if got := scalar(`SELECT status FROM access_requests WHERE id = $1`, request); got != "expired" {
		t.Fatalf("the request's window closed and it is %q, want expired", got)
	}
	if n := told(requester, "request_update", request, "window"); n != 1 {
		t.Errorf("the requester holds %d ended notifications, want 1", n)
	}
	if n := len(pub.of("access_request.ended", request)); n != 1 {
		t.Errorf("access_request.ended published %d times, want 1", n)
	}

	// Denied: the requester is told.
	denied := file(oneStep)
	if code, body := call(first, "/requests/"+denied+"/deny", `{"comments":"no"}`); code != http.StatusOK {
		t.Fatalf("deny: %d %v", code, body)
	}
	if n := told(requester, "request_update", denied, "denied"); n != 1 {
		t.Errorf("the requester holds %d denied notifications, want 1", n)
	}
	if n := len(pub.of("access_request.denied", denied)); n != 1 {
		t.Errorf("access_request.denied published %d times, want 1", n)
	}

	// Nobody answered in time: the requester is told it expired.
	waiting := file(unanswered)
	exec(`UPDATE access_requests SET answer_by = NOW() - INTERVAL '1 minute' WHERE id = $1`, waiting)
	s.revokeExpiredJITAccess(sweep)
	if n := told(requester, "request_update", waiting, "unanswered"); n != 1 {
		t.Errorf("the requester holds %d unanswered notifications, want 1", n)
	}
	if n := len(pub.of("access_request.ended", waiting)); n != 1 {
		t.Errorf("access_request.ended published %d times for the unanswered request, want 1", n)
	}

	// Switched off: not told, and published all the same.
	exec(`INSERT INTO notification_preferences (user_id, channel, event_type, enabled) VALUES ($1, 'in_app', 'request_update', false)`, requester)
	silent := file(quiet)
	if code, body := call(first, "/requests/"+silent+"/deny", `{"comments":"no"}`); code != http.StatusOK {
		t.Fatalf("deny: %d %v", code, body)
	}
	if n := told(requester, "request_update", silent, ""); n != 0 {
		t.Errorf("a requester who switched request_update off holds %d notifications", n)
	}
	if n := len(pub.of("access_request.denied", silent)); n != 1 {
		t.Errorf("access_request.denied published %d times for a requester who switched notifications off, want 1", n)
	}

	// Every event went to this organization's subscribers, and no bypass.
	for _, e := range pub.all() {
		if e.Org != org || e.Bypass {
			t.Errorf("%s published under org %q (bypass %v), want %s and no bypass", e.Type, e.Org, e.Bypass, org)
		}
	}
}
