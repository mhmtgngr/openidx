package governance

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

// The approval endpoint — where a request becomes access.
//
// Two things it owes the people using it: it must not let someone approve
// their own request, and it must not report success for a grant that did not
// happen. Neither was true, and no test named the handler.

const (
	arOrg   = "00000000-0000-0000-0000-000000000010"
	arAlice = "11111111-1111-1111-1111-111111111111" // requester
	arBob   = "22222222-2222-2222-2222-222222222222" // approver
	arRole  = "33333333-3333-3333-3333-333333333333"
)

const approvalSchema = `
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, org_id UUID, username VARCHAR(255), enabled BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS roles (id UUID PRIMARY KEY, name VARCHAR(255), org_id UUID);
CREATE TABLE IF NOT EXISTS user_roles (user_id UUID, role_id UUID, org_id UUID, expires_at TIMESTAMPTZ, PRIMARY KEY (user_id, role_id));
CREATE TABLE IF NOT EXISTS groups (id UUID PRIMARY KEY, name VARCHAR(255), org_id UUID);
CREATE TABLE IF NOT EXISTS group_memberships (user_id UUID, group_id UUID, org_id UUID, PRIMARY KEY (user_id, group_id));
CREATE TABLE IF NOT EXISTS policies (id UUID PRIMARY KEY, name TEXT, type TEXT, enabled BOOLEAN DEFAULT TRUE, org_id UUID);
CREATE TABLE IF NOT EXISTS policy_rules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE, rule_type TEXT,
    conditions JSONB NOT NULL, actions JSONB, org_id UUID);
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL, requester_id UUID NOT NULL,
    resource_type VARCHAR(64), resource_id VARCHAR(255), resource_name VARCHAR(255),
    justification TEXT, status VARCHAR(32) NOT NULL DEFAULT 'pending',
    priority VARCHAR(32) DEFAULT 'normal', expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS access_request_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL, approver_id UUID NOT NULL, step_order INT,
    decision VARCHAR(32) NOT NULL DEFAULT 'pending', comments TEXT,
    decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID NOT NULL);`

type approvalFixture struct {
	svc *Service
	ctx context.Context
	t   *testing.T
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, approvalSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	f := &approvalFixture{svc: &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}, ctx: ctx, t: t}
	f.exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$3,'alice'),($2,$3,'bob')`, arAlice, arBob, arOrg)
	f.exec(`INSERT INTO roles (id, name, org_id) VALUES ($1,'reader',$2)`, arRole, arOrg)
	return f
}

func (f *approvalFixture) exec(sql string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.svc.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// request creates a pending role request from arAlice with one pending
// approval row for each named approver.
func (f *approvalFixture) request(resourceType, resourceID string, approvers ...string) string {
	f.t.Helper()
	var id string
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification)
		 VALUES ($1,$2,$3,$4,'thing','because') RETURNING id`,
		arOrg, arAlice, resourceType, resourceID).Scan(&id); err != nil {
		f.t.Fatalf("create request: %v", err)
	}
	for i, a := range approvers {
		f.exec(`INSERT INTO access_request_approvals (request_id, approver_id, step_order, org_id)
		        VALUES ($1,$2,$3,$4)`, id, a, i+1, arOrg)
	}
	return id
}

// approveAs runs handleApproveRequest as `caller` and returns the response.
func (f *approvalFixture) approveAs(requestID, caller string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/governance/requests/"+requestID+"/approve",
		bytes.NewBufferString(`{"comments":"ok"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: arOrg}))
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: requestID}}
	c.Set("user_id", caller)

	f.svc.handleApproveRequest(c)
	return w
}

func (f *approvalFixture) requestStatus(id string) string {
	f.t.Helper()
	var status string
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT status FROM access_requests WHERE id = $1`, id).Scan(&status); err != nil {
		f.t.Fatalf("read status: %v", err)
	}
	return status
}

func (f *approvalFixture) holdsRole(user, role string) bool {
	f.t.Helper()
	var n int
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT count(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, user, role).Scan(&n); err != nil {
		f.t.Fatalf("count roles: %v", err)
	}
	return n > 0
}

func body(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

// --------------------------------------------------------------------------

// Four eyes. createApprovalRows excludes the requester when it expands a role-
// or group-based step, which is the right place to PREVENT the row — but it is
// not the only route to one. An escalate_to target is inserted with no such
// check, a policy step may name the requester outright, the no-policy fallback
// inserts a fixed admin id, and rows written before that guard existed are
// still in the table. All of them arrive here, and here there was no check at
// all. Red before the fix: the approval landed and the role was granted.
func TestApproveRequestRefusesSelfApproval(t *testing.T) {
	f := newApprovalFixture(t)
	// Alice is somehow her own approver.
	id := f.request("role", arRole, arAlice)

	w := f.approveAs(id, arAlice)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if f.requestStatus(id) != "pending" {
		t.Errorf("status = %q after a refused self-approval, want pending", f.requestStatus(id))
	}
	if f.holdsRole(arAlice, arRole) {
		t.Error("the requester granted themselves the role by approving their own request")
	}

	var decision string
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT decision FROM access_request_approvals WHERE request_id=$1`, id).Scan(&decision); err != nil {
		t.Fatalf("read decision: %v", err)
	}
	if decision != "pending" {
		t.Errorf("decision = %q, want pending — the refusal must not record an approval", decision)
	}
}

// The ordinary path, and the one thing it must say correctly: the access
// exists. 'approved' means a decision was made; 'fulfilled' means the grant
// happened, and only fulfillRequest may write it.
func TestApproveRequestFulfilsAndSaysSo(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob)

	w := f.approveAs(id, arBob)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if got := body(t, w)["status"]; got != "fulfilled" {
		t.Errorf("response status = %v, want fulfilled", got)
	}
	if st := f.requestStatus(id); st != "fulfilled" {
		t.Errorf("request status = %q, want fulfilled", st)
	}
	if !f.holdsRole(arAlice, arRole) {
		t.Error("the request was fulfilled but the role was not granted")
	}
}

// The failure this handler used to hide. fulfillRequest returns an error for an
// unsupported resource type — its own comment says failing loudly there is the
// point — and the handler logged it and answered "Request approved
// successfully". The approver was told the access existed; it did not, and the
// request sat at 'approved' with nobody looking.
func TestApproveRequestReportsAFulfilmentFailure(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("teleporter", "nowhere", arBob)

	w := f.approveAs(id, arBob)
	if w.Code == http.StatusOK {
		t.Fatalf("status = 200 for a request whose access was never granted (body=%s)", w.Body.String())
	}
	got := body(t, w)
	if got["error"] == nil {
		t.Errorf("body = %v; the approver has to be told the grant did not happen", got)
	}
	// The decision stands — it was made — but the request must not claim the
	// access exists.
	if st := f.requestStatus(id); st != "approved" {
		t.Errorf("request status = %q, want approved (decided, not granted)", st)
	}
}

// A multi-approver request is not granted by the first approval. The response
// has to say that, or the first approver believes they finished it.
func TestApproveRequestWaitsForTheRemainingApprovers(t *testing.T) {
	f := newApprovalFixture(t)
	third := "44444444-4444-4444-4444-444444444444"
	f.exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'carol')`, third, arOrg)
	id := f.request("role", arRole, arBob, third)

	w := f.approveAs(id, arBob)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if got := body(t, w)["status"]; got != "pending" {
		t.Errorf("response status = %v, want pending while another approver has not decided", got)
	}
	if st := f.requestStatus(id); st != "pending" {
		t.Errorf("request status = %q, want pending", st)
	}
	if f.holdsRole(arAlice, arRole) {
		t.Error("access was granted on the first of two required approvals")
	}

	// The second approval completes it.
	w = f.approveAs(id, third)
	if w.Code != http.StatusOK {
		t.Fatalf("second approval: status = %d (body=%s)", w.Code, w.Body.String())
	}
	if st := f.requestStatus(id); st != "fulfilled" {
		t.Errorf("request status = %q after every approval, want fulfilled", st)
	}
}

// Someone who is not an approver on this request cannot approve it, and a
// second approval from the same person is not a second approval.
func TestApproveRequestRefusesANonApproverAndADoubleApproval(t *testing.T) {
	f := newApprovalFixture(t)
	stranger := "55555555-5555-5555-5555-555555555555"
	id := f.request("role", arRole, arBob)

	if w := f.approveAs(id, stranger); w.Code != http.StatusNotFound {
		t.Errorf("stranger: status = %d, want 404 (body=%s)", w.Code, w.Body.String())
	}
	if w := f.approveAs(id, arBob); w.Code != http.StatusOK {
		t.Fatalf("approver: status = %d (body=%s)", w.Code, w.Body.String())
	}
	if w := f.approveAs(id, arBob); w.Code != http.StatusNotFound {
		t.Errorf("second approval by the same approver: status = %d, want 404", w.Code)
	}
}

// An approval names a request by id, and the id is a path parameter. Another
// tenant's request must answer what a non-existent one answers.
func TestApproveRequestWillNotReachIntoAnotherTenant(t *testing.T) {
	f := newApprovalFixture(t)
	const otherOrg = "00000000-0000-0000-0000-0000000000b0"

	var id string
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification)
		 VALUES ($1,$2,'role',$3,'thing','because') RETURNING id`, otherOrg, arAlice, arRole).Scan(&id); err != nil {
		t.Fatalf("create foreign request: %v", err)
	}
	f.exec(`INSERT INTO access_request_approvals (request_id, approver_id, step_order, org_id)
	        VALUES ($1,$2,1,$3)`, id, arBob, otherOrg)

	w := f.approveAs(id, arBob) // runs under arOrg
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another tenant's request (body=%s)", w.Code, w.Body.String())
	}
	if st := f.requestStatus(id); st != "pending" {
		t.Errorf("the foreign request became %q", st)
	}
}

// No caller identity, or no organization: refuse before touching anything.
func TestApproveRequestRequiresACallerAndAnOrganization(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob)

	gin.SetMode(gin.TestMode)
	run := func(caller string, withOrg bool) int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.Background()
		if withOrg {
			ctx = orgctx.With(ctx, orgctx.Org{ID: arOrg})
		}
		c.Request = req.WithContext(ctx)
		c.Params = gin.Params{{Key: "id", Value: id}}
		if caller != "" {
			c.Set("user_id", caller)
		}
		f.svc.handleApproveRequest(c)
		return w.Code
	}

	if got := run("", true); got != http.StatusUnauthorized {
		t.Errorf("no caller: status = %d, want 401", got)
	}
	if got := run(arBob, false); got != http.StatusForbidden {
		t.Errorf("no organization: status = %d, want 403", got)
	}
	if f.requestStatus(id) != "pending" {
		t.Error("a refused approval changed the request")
	}
}
