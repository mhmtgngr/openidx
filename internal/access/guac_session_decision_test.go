package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Approving a remote-desktop session request.
//
// `require_approval` on a Guacamole connection means handleGuacamoleConnect
// will not start the session until a request for it has been approved, and
// that gate has no administrator bypass. Both decision routes are admin-only,
// so an administrator who requests a session for a gated connection and then
// approves it is the gate approving nothing.

const (
	guacOrg      = "00000000-0000-0000-0000-000000000010"
	guacAdmin    = "00000000-0000-0000-0000-0000000000a5"
	guacOther    = "00000000-0000-0000-0000-0000000000a6"
	guacConnPK   = "00000000-0000-0000-0000-0000000000c5"
	guacOtherOrg = "00000000-0000-0000-0000-0000000000b0"
)

type guacFixture struct {
	svc *Service
	ctx context.Context
	t   *testing.T
}

func newGuacDecisionFixture(t *testing.T) *guacFixture {
	t.Helper()
	db := pamRevealTestDB(t)
	svc := NewService(db, nil, &config.Config{AccessSessionSecret: "guac-decision-test-session-secret"}, zap.NewNop())
	f := &guacFixture{svc: svc, ctx: orgctx.With(context.Background(), orgctx.Org{ID: guacOrg}), t: t}
	f.exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,'other','other-guac') ON CONFLICT DO NOTHING`, guacOtherOrg)
	return f
}

func (f *guacFixture) exec(sql string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.svc.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// sessionRequest inserts a pending request from `requester` in `org`.
func (f *guacFixture) sessionRequest(org, requester string) string {
	f.t.Helper()
	ctx := f.ctx
	if org != guacOrg {
		// Written the way the other tenant's own request would write it.
		ctx = orgctx.WithBypassRLS(f.ctx)
	}
	var id string
	if err := f.svc.db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_session_requests (org_id, connection_id, requester_id, reason)
		VALUES ($1,$2,$3,'maintenance') RETURNING id`, org, guacConnPK, requester).Scan(&id); err != nil {
		f.t.Fatalf("create session request: %v", err)
	}
	return id
}

func (f *guacFixture) decide(handler gin.HandlerFunc, requestID, caller string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(f.ctx)
	c.Params = gin.Params{{Key: "id", Value: requestID}}
	c.Set("user_id", caller)
	c.Set("roles", []string{"admin"})
	handler(c)
	return w
}

func (f *guacFixture) status(id string) string {
	f.t.Helper()
	var st string
	if err := f.svc.db.Pool.QueryRow(orgctx.WithBypassRLS(f.ctx),
		`SELECT status FROM guacamole_session_requests WHERE id = $1`, id).Scan(&st); err != nil {
		f.t.Fatalf("read status: %v", err)
	}
	return st
}

// --------------------------------------------------------------------------

// Red before the fix: the request went to 'approved' and the connection gate
// had been satisfied by the person it was meant to gate.
func TestGuacSessionApprovalRefusesTheRequester(t *testing.T) {
	f := newGuacDecisionFixture(t)
	id := f.sessionRequest(guacOrg, guacAdmin)

	w := f.decide(f.svc.handleApproveGuacSession, id, guacAdmin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if st := f.status(id); st != "pending" {
		t.Errorf("request is %q after a refused self-approval, want pending", st)
	}
}

// Denying your own request is a withdrawal, not an escalation, so it stands.
func TestGuacSessionDenialByTheRequesterIsAllowed(t *testing.T) {
	f := newGuacDecisionFixture(t)
	id := f.sessionRequest(guacOrg, guacAdmin)

	w := f.decide(f.svc.handleDenyGuacSession, id, guacAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if st := f.status(id); st != "denied" {
		t.Errorf("request is %q, want denied", st)
	}
}

// Somebody else approving it is the ordinary path.
func TestGuacSessionApprovalBySomeoneElseSucceeds(t *testing.T) {
	f := newGuacDecisionFixture(t)
	id := f.sessionRequest(guacOrg, guacOther)

	w := f.decide(f.svc.handleApproveGuacSession, id, guacAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "approved" {
		t.Errorf("response status = %v, want approved", body["status"])
	}
	if st := f.status(id); st != "approved" {
		t.Errorf("request is %q, want approved", st)
	}
	// And a second decision on the same request finds nothing pending.
	if w := f.decide(f.svc.handleApproveGuacSession, id, guacAdmin); w.Code != http.StatusNotFound {
		t.Errorf("second decision: status = %d, want 404", w.Code)
	}
}

// Another tenant's request answers what an unknown id answers, and is left
// alone.
func TestGuacSessionDecisionWillNotReachIntoAnotherTenant(t *testing.T) {
	f := newGuacDecisionFixture(t)
	foreign := f.sessionRequest(guacOtherOrg, guacOther)

	unknown := f.decide(f.svc.handleApproveGuacSession, "00000000-0000-0000-0000-0000000000ff", guacAdmin)
	other := f.decide(f.svc.handleApproveGuacSession, foreign, guacAdmin)

	if other.Code != unknown.Code || other.Body.String() != unknown.Body.String() {
		t.Errorf("another tenant's request answers %d %s; an unknown id answers %d %s — they must be identical",
			other.Code, other.Body.String(), unknown.Code, unknown.Body.String())
	}
	if st := f.status(foreign); st != "pending" {
		t.Errorf("the foreign request became %q", st)
	}
}

// No organization context: refuse before the request is read at all.
func TestGuacSessionDecisionRequiresAnOrganization(t *testing.T) {
	f := newGuacDecisionFixture(t)
	id := f.sessionRequest(guacOrg, guacOther)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
	c.Request = req.WithContext(context.Background())
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("user_id", guacAdmin)

	f.svc.handleApproveGuacSession(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if st := f.status(id); st != "pending" {
		t.Errorf("request is %q after a refused decision, want pending", st)
	}
}
