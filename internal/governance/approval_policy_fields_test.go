package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The three approval-policy fields the console has always shown and the
// workflow never read: a step's min_approvals, the order of the steps, and
// the policy's max_wait_hours. Each is driven through the real handlers on
// the fixture schema with the v212 columns, both ways: the case the field
// allows and the case it refuses.

const (
	apDave        = "55555555-5555-5555-5555-555555555555"
	apErin        = "66666666-6666-6666-6666-666666666666"
	apApproverRol = "77777777-7777-7777-7777-777777777777"
)

// createAs files a role request for arRole through handleCreateAccessRequest
// as `caller`, returning the response.
func (f *approvalFixture) createAs(caller, resourceType, resourceID string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	payload, _ := json.Marshal(map[string]string{
		"resource_type": resourceType, "resource_id": resourceID, "resource_name": "thing", "justification": "because",
	})
	req := httptest.NewRequest(http.MethodPost, "/governance/requests", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: arOrg}))
	c.Request = req
	c.Set("user_id", caller)
	f.svc.handleCreateAccessRequest(c)
	return w
}

// queueOf is the request ids handleListPendingApprovals shows `caller`.
func (f *approvalFixture) queueOf(caller string) []string {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/governance/my-approvals", nil)
	req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: arOrg}))
	c.Request = req
	c.Set("user_id", caller)
	f.svc.handleListPendingApprovals(c)
	if w.Code != http.StatusOK {
		f.t.Fatalf("my-approvals for %s: %d %s", caller, w.Code, w.Body.String())
	}
	var out struct {
		Pending []AccessRequest `json:"pending_approvals"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode my-approvals: %v", err)
	}
	ids := make([]string, 0, len(out.Pending))
	for _, r := range out.Pending {
		ids = append(ids, r.ID)
	}
	return ids
}

func (f *approvalFixture) decisionOf(requestID, approver string) string {
	f.t.Helper()
	var d string
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT decision FROM access_request_approvals WHERE request_id = $1 AND approver_id = $2`, requestID, approver).Scan(&d); err != nil {
		f.t.Fatalf("read decision of %s: %v", approver, err)
	}
	return d
}

func (f *approvalFixture) policy(steps string, maxWaitHours int) {
	f.t.Helper()
	f.exec(`INSERT INTO approval_policies (name, resource_type, approval_steps, max_wait_hours, enabled, org_id)
	        VALUES ('roles', 'role', $1::jsonb, $2, true, $3)`, steps, maxWaitHours, arOrg)
}

func (f *approvalFixture) seedApprovers() {
	f.t.Helper()
	f.exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$3,'dave'),($2,$3,'erin')`, apDave, apErin, arOrg)
	f.exec(`INSERT INTO roles (id, name, org_id) VALUES ($1,'approvers',$2)`, apApproverRol, arOrg)
	f.exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$4,$5),($2,$4,$5),($3,$4,$5)`,
		arBob, arCarol, apDave, apApproverRol, arOrg)
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestApprovalStepsRunInOrderAndCountMinApprovals(t *testing.T) {
	f := newApprovalFixture(t)
	f.seedApprovers()
	// Step 1: two of the three approvers. Step 2: erin.
	f.policy(`[{"order":1,"type":"role","role_id":"`+apApproverRol+`","min_approvals":2},
	           {"order":2,"type":"specific_user","approver_id":"`+apErin+`"}]`, 48)

	w := f.createAs(arAlice, "role", arRole)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := body(t, w)["id"].(string)

	var rows, need2 int
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE step_min_approvals = 2 AND step_order = 1)
		   FROM access_request_approvals WHERE request_id = $1`, id).Scan(&rows, &need2); err != nil {
		t.Fatal(err)
	}
	if rows != 4 || need2 != 3 {
		t.Fatalf("chain: %d rows, %d step-1 rows needing 2 approvals; want 4 and 3", rows, need2)
	}
	var hasDeadline bool
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT answer_by IS NOT NULL AND answer_by > NOW() + INTERVAL '47 hours' FROM access_requests WHERE id = $1`, id).Scan(&hasDeadline); err != nil {
		t.Fatal(err)
	}
	if !hasDeadline {
		t.Error("the policy's 48-hour wait was not recorded on the request")
	}

	// Step 2 cannot go first: erin is told to wait, and her queue is empty.
	if w := f.approveAs(id, apErin); w.Code != http.StatusConflict {
		t.Errorf("step-2 approver before step 1: %d, want 409 (body=%s)", w.Code, w.Body.String())
	}
	if f.decisionOf(id, apErin) != "pending" {
		t.Error("the refused early approval was recorded")
	}
	if contains(f.queueOf(apErin), id) {
		t.Error("erin's queue shows a request that is not at her step")
	}
	if !contains(f.queueOf(arBob), id) {
		t.Error("bob's queue does not show the request at his step")
	}

	// One of two: still step 1.
	w = f.approveAs(id, arBob)
	if w.Code != http.StatusOK || body(t, w)["status"] != "pending" || body(t, w)["step"] != float64(1) {
		t.Fatalf("first step-1 approval: %d %s, want pending at step 1", w.Code, w.Body.String())
	}
	// Two of two: step 1 done, dave's row skipped, step 2 active.
	w = f.approveAs(id, arCarol)
	if w.Code != http.StatusOK || body(t, w)["status"] != "pending" || body(t, w)["step"] != float64(2) {
		t.Fatalf("second step-1 approval: %d %s, want pending at step 2", w.Code, w.Body.String())
	}
	if d := f.decisionOf(id, apDave); d != "skipped" {
		t.Errorf("dave's row after step 1 was satisfied = %q, want skipped", d)
	}
	if contains(f.queueOf(apDave), id) {
		t.Error("dave's queue still shows a step his approval no longer counts for")
	}
	if !contains(f.queueOf(apErin), id) {
		t.Error("erin's queue does not show the request now at her step")
	}
	if w := f.approveAs(id, apDave); w.Code != http.StatusNotFound {
		t.Errorf("a skipped approver could still decide: %d", w.Code)
	}
	if f.holdsRole(arAlice, arRole) {
		t.Fatal("the role was granted before step 2 decided")
	}

	// Step 2 decides, and the access exists.
	w = f.approveAs(id, apErin)
	if w.Code != http.StatusOK || body(t, w)["status"] != "fulfilled" {
		t.Fatalf("step-2 approval: %d %s, want fulfilled", w.Code, w.Body.String())
	}
	if !f.holdsRole(arAlice, arRole) {
		t.Error("every step approved and the role was not granted")
	}
}

func TestAStepShortOfItsMinApprovalsRefusesTheRequest(t *testing.T) {
	f := newApprovalFixture(t)
	// The approver role has one holder and the step wants two.
	f.exec(`INSERT INTO roles (id, name, org_id) VALUES ($1,'approvers',$2)`, apApproverRol, arOrg)
	f.exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, arBob, apApproverRol, arOrg)
	f.policy(`[{"order":1,"type":"role","role_id":"`+apApproverRol+`","min_approvals":2}]`, 0)

	w := f.createAs(arAlice, "role", arRole)
	if w.Code != http.StatusConflict {
		t.Fatalf("create under an unsatisfiable policy: %d %s, want 409", w.Code, w.Body.String())
	}
	if body(t, w)["code"] != "approval_chain_unbuildable" {
		t.Errorf("code = %v, want approval_chain_unbuildable", body(t, w)["code"])
	}
	var n int
	if err := f.svc.db.Pool.QueryRow(f.ctx, `SELECT COUNT(*) FROM access_requests WHERE org_id = $1`, arOrg).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d request rows stand after the refusal; want none", n)
	}

	// The same step with a second holder is satisfiable.
	f.exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, arCarol, apApproverRol, arOrg)
	if w := f.createAs(arAlice, "role", arRole); w.Code != http.StatusCreated {
		t.Fatalf("create once the step can be met: %d %s", w.Code, w.Body.String())
	}
}

func TestADenialWaitsForItsStepToo(t *testing.T) {
	f := newApprovalFixture(t)
	f.policy(`[{"order":1,"type":"specific_user","approver_id":"`+arBob+`"},
	           {"order":2,"type":"specific_user","approver_id":"`+arCarol+`"}]`, 0)
	w := f.createAs(arAlice, "role", arRole)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := body(t, w)["id"].(string)

	if w := f.denyAs(id, arCarol); w.Code != http.StatusConflict {
		t.Errorf("step-2 denial before step 1: %d, want 409", w.Code)
	}
	if st := f.requestStatus(id); st != "pending" {
		t.Errorf("status after the refused early denial = %q, want pending", st)
	}
	if w := f.denyAs(id, arBob); w.Code != http.StatusOK {
		t.Fatalf("step-1 denial: %d %s", w.Code, w.Body.String())
	}
	if st := f.requestStatus(id); st != "denied" {
		t.Errorf("status after step 1 denied = %q, want denied", st)
	}
	// No policy: the fallback single row still decides alone.
	var deadline *string
	if err := f.svc.db.Pool.QueryRow(f.ctx, `SELECT answer_by::text FROM access_requests WHERE id = $1`, id).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if deadline != nil {
		t.Errorf("a policy with max_wait_hours 0 recorded a deadline %s", *deadline)
	}
}

func TestAnUnansweredRequestExpiresAtThePolicysWait(t *testing.T) {
	f := newApprovalFixture(t)
	f.policy(`[{"order":1,"type":"specific_user","approver_id":"`+arBob+`"}]`, 1)
	w := f.createAs(arAlice, "role", arRole)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	timed := body(t, w)["id"].(string)
	// A request filed before deadlines existed: answer_by NULL, waits as ever.
	untimed := f.request("role", arRole, arBob)

	// The clock runs out on the first.
	f.exec(`UPDATE access_requests SET answer_by = NOW() - INTERVAL '1 minute' WHERE id = $1`, timed)
	f.svc.expireUnansweredRequests(orgctx.WithBypassRLS(f.ctx))

	if st := f.requestStatus(timed); st != "expired" {
		t.Errorf("unanswered request past its wait = %q, want expired", st)
	}
	if d := f.decisionOf(timed, arBob); d != "expired" {
		t.Errorf("its approval row = %q, want expired", d)
	}
	var audits int
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = 'access_request.expired_unanswered' AND org_id = $1`, arOrg).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Errorf("%d audit rows for the expiry, want 1", audits)
	}
	if w := f.approveAs(timed, arBob); w.Code != http.StatusConflict {
		t.Errorf("approving an expired request: %d, want 409", w.Code)
	}
	if f.holdsRole(arAlice, arRole) {
		t.Error("an expired request granted the role")
	}
	if contains(f.queueOf(arBob), timed) {
		t.Error("bob's queue still shows the expired request")
	}

	// The untimed one is untouched, and a second sweep changes nothing.
	if st := f.requestStatus(untimed); st != "pending" {
		t.Errorf("request with no deadline = %q, want pending", st)
	}
	f.svc.expireUnansweredRequests(orgctx.WithBypassRLS(f.ctx))
	if err := f.svc.db.Pool.QueryRow(f.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = 'access_request.expired_unanswered' AND org_id = $1`, arOrg).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Errorf("a second sweep wrote more audit rows: %d", audits)
	}
}
