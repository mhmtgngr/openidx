package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// An approval chain that came out shorter than its policy must not stand.
//
// Every INSERT into access_request_approvals used to discard its error -- five
// of them, one per step type. Losing the whole chain is visible enough: nobody
// can approve the request, because handleApproveRequest requires the approver's
// own pending row and answers "No pending approval found for this approver".
//
// Losing PART of it is the dangerous one, and it is silent. handleApproveRequest
// fulfils a request when `SELECT COUNT(*) ... WHERE decision = 'pending'` reaches
// zero. If a two-step policy produced only its first row, the one approver who
// did get a row approves, the count reaches zero, and the request is granted
// having skipped a step its policy required -- with an audit trail saying it was
// approved.
//
// So the chain builder reports failure now, and the handler withdraws the
// request rather than leaving a half-routed one behind.

const chainOrgID = "00000000-0000-0000-0000-000000000030"

// breakSecondApprovalRow makes the INSERT of step 2 fail the way a policy, a
// constraint or a dropped connection would. A trigger is used rather than
// dropping the table because the chain builder reads other tables first: the
// failure has to arrive at the write, not before it.
const breakSecondApprovalRow = `
CREATE FUNCTION refuse_second_step() RETURNS trigger AS $$
BEGIN
	IF NEW.step_order = 2 THEN
		RAISE EXCEPTION 'refusing the second approval row';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER refuse_second_step BEFORE INSERT ON access_request_approvals
FOR EACH ROW EXECUTE FUNCTION refuse_second_step();`

func TestAHalfBuiltApprovalChainIsReported(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: chainOrgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE approval_policies (
			id UUID PRIMARY KEY,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			approval_steps JSONB NOT NULL,
			auto_approve_conditions JSONB,
			enabled BOOLEAN DEFAULT true,
			org_id UUID NOT NULL);
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY,
			requester_id UUID NOT NULL,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			resource_name TEXT,
			justification TEXT,
			status VARCHAR(20) NOT NULL,
			priority VARCHAR(20),
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now(),
			updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
		CREATE TABLE access_request_approvals (
			id UUID PRIMARY KEY,
			request_id UUID NOT NULL,
			approver_id UUID NOT NULL,
			step_order INTEGER NOT NULL,
			decision VARCHAR(20) NOT NULL,
			comments TEXT,
			decided_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		policyID  = "cccccccc-0000-0000-0000-000000000030"
		requestID = "eeeeeeee-0000-0000-0000-000000000030"
		approver1 = "bbbbbbbb-0000-0000-0000-000000000031"
		approver2 = "bbbbbbbb-0000-0000-0000-000000000032"
		requester = "bbbbbbbb-0000-0000-0000-000000000039"
	)

	steps := fmt.Sprintf(
		`[{"order":1,"type":"specific_user","approver_id":"%s"},{"order":2,"type":"specific_user","approver_id":"%s"}]`,
		approver1, approver2)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO approval_policies (id, resource_type, resource_id, approval_steps, enabled, org_id)
		 VALUES ($1, 'role', NULL, $2, true, $3)`, policyID, steps, chainOrgID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	// With both writes working, a two-step policy makes two rows.
	if err := s.createApprovalRows(ctx, requestID, "role", "ffffffff-0000-0000-0000-000000000030"); err != nil {
		t.Fatalf("a policy whose writes all succeed must build its chain: %v", err)
	}
	var built int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id = $1 AND org_id = $2`,
		requestID, chainOrgID).Scan(&built); err != nil {
		t.Fatalf("count approvals: %v", err)
	}
	if built != 2 {
		t.Fatalf("built %d approval row(s) for a two-step policy, want 2 — if this is 0 the rest of this "+
			"test proves nothing, because a builder that writes no rows cannot fail on the second", built)
	}

	// Now refuse the second step's row and try again on a fresh request.
	if _, err := db.Pool.Exec(ctx, breakSecondApprovalRow); err != nil {
		t.Fatalf("install the failure: %v", err)
	}
	const secondRequest = "eeeeeeee-0000-0000-0000-000000000031"
	err := s.createApprovalRows(ctx, secondRequest, "role", "ffffffff-0000-0000-0000-000000000030")
	if err == nil {
		t.Fatal("a policy step whose approval row could not be written reported success. " +
			"The request now has one approver where its policy names two: that approver approves, the pending " +
			"count reaches zero, and the request is fulfilled with a required approval skipped.")
	}

	// And the half that did land must not be left behind as a usable chain.
	var partial int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id = $1 AND org_id = $2`,
		secondRequest, chainOrgID).Scan(&partial); err != nil {
		t.Fatalf("count approvals: %v", err)
	}
	if partial >= 2 {
		t.Fatalf("the second step's row was written after all (%d rows); the failure injection did not take, "+
			"so this test is not exercising what it claims", partial)
	}
	_ = requester
}

// The handler half: a request whose chain cannot be built is withdrawn, and the
// caller is told, rather than being answered 201 with a request that can be
// fulfilled without the approvals its policy requires.
func TestARequestWhoseChainFailsIsWithdrawn(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: chainOrgID})
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE approval_policies (
			id UUID PRIMARY KEY,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			approval_steps JSONB NOT NULL,
			auto_approve_conditions JSONB,
			enabled BOOLEAN DEFAULT true,
			org_id UUID NOT NULL);
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY,
			requester_id UUID NOT NULL,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			resource_name TEXT,
			justification TEXT,
			status VARCHAR(20) NOT NULL,
			priority VARCHAR(20),
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now(),
			updated_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
		CREATE TABLE access_request_approvals (
			id UUID PRIMARY KEY,
			request_id UUID NOT NULL,
			approver_id UUID NOT NULL,
			step_order INTEGER NOT NULL,
			decision VARCHAR(20) NOT NULL,
			comments TEXT,
			decided_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now(),
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		policyID  = "cccccccc-0000-0000-0000-000000000040"
		approver1 = "bbbbbbbb-0000-0000-0000-000000000041"
		approver2 = "bbbbbbbb-0000-0000-0000-000000000042"
		requester = "bbbbbbbb-0000-0000-0000-000000000049"
	)
	steps := fmt.Sprintf(
		`[{"order":1,"type":"specific_user","approver_id":"%s"},{"order":2,"type":"specific_user","approver_id":"%s"}]`,
		approver1, approver2)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO approval_policies (id, resource_type, resource_id, approval_steps, enabled, org_id)
		 VALUES ($1, 'role', NULL, $2, true, $3)`, policyID, steps, chainOrgID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, breakSecondApprovalRow); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	gin.SetMode(gin.TestMode)
	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	body, _ := json.Marshal(map[string]string{
		"resource_type": "role",
		"resource_id":   "ffffffff-0000-0000-0000-000000000040",
		"resource_name": "Payments admin",
		"justification": "on call this week",
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/access-requests", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(ctx)
	c.Set("user_id", requester)

	s.handleCreateAccessRequest(c)

	if w.Code == http.StatusCreated {
		t.Errorf("answered 201 for a request whose approval chain could not be built. "+
			"The requester believes the request is routed; the one approver who got a row can fulfil it alone. "+
			"body: %s", w.Body.String())
	}

	var left int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_requests WHERE org_id = $1`, chainOrgID).Scan(&left); err != nil {
		t.Fatalf("count requests: %v", err)
	}
	if left != 0 {
		t.Errorf("%d access request(s) survive with an approval chain shorter than their policy; "+
			"each can be fulfilled by the approvers who did get a row", left)
	}
}
