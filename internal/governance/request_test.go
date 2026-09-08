package governance

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// This file used to hold nine test functions and fourteen subtests, every one
// of them a single unconditional t.Skip("DB mock not available - requires
// integration test"). They were named TestSubmitRequest, TestApproveRequest,
// TestDenyRequest -- after methods this service has never had. The workflow is
// handleCreateAccessRequest / handleApproveRequest / handleDenyRequest /
// handleCancelRequest, and this package has carried a container-backed
// setupTestDB the whole time.
//
// approve_request_test.go covers the approval side properly. Denial and
// cancellation had nothing, and denial turned out to be where the interesting
// defect was.

// denyAs runs handleDenyRequest as `caller`.
func (f *approvalFixture) denyAs(requestID, caller string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.callAs(f.svc.handleDenyRequest, requestID, caller, `{"comments":"no"}`)
}

// cancelAs runs handleCancelRequest as `caller`.
func (f *approvalFixture) cancelAs(requestID, caller string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.callAs(f.svc.handleCancelRequest, requestID, caller, "")
}

func (f *approvalFixture) callAs(h gin.HandlerFunc, requestID, caller, jsonBody string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/governance/requests/"+requestID+"/decide",
		bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: arOrg}))
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: requestID}}
	if caller != "" {
		c.Set("user_id", caller)
	}
	h(c)
	return w
}

func TestDenyRequestRecordsTheDecision(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob)

	w := f.denyAs(id, arBob)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if got := f.requestStatus(id); got != "denied" {
		t.Errorf("request status = %q, want denied", got)
	}
	if f.holdsRole(arAlice, arRole) {
		t.Error("a denied request granted the role")
	}
}

func TestDenyRequestRefusesANonApproverAndADoubleDecision(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob)

	// Alice has no approval row on her own request.
	if w := f.denyAs(id, arAlice); w.Code != http.StatusNotFound {
		t.Errorf("a non-approver denial returned %d, want 404", w.Code)
	}
	if got := f.requestStatus(id); got != "pending" {
		t.Fatalf("a refused denial still moved the request to %q", got)
	}

	if w := f.denyAs(id, arBob); w.Code != http.StatusOK {
		t.Fatalf("the approver's denial returned %d", w.Code)
	}
	// The row is no longer pending, so a second decision has nothing to act on.
	if w := f.denyAs(id, arBob); w.Code != http.StatusNotFound {
		t.Errorf("a second denial returned %d, want 404", w.Code)
	}
}

func TestDenyRequestRequiresACallerAndAnOrganization(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob)

	if w := f.denyAs(id, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated denial returned %d, want 401", w.Code)
	}

	// No org on the request context.
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString("{}"))
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("user_id", arBob)
	f.svc.handleDenyRequest(c)
	if w.Code != http.StatusForbidden {
		t.Errorf("a denial with no organization returned %d, want 403", w.Code)
	}
}

// ONE denial ends the request. With two approvers pending, the first "no" is
// final rather than one vote among several -- which is the right rule for
// access, and worth pinning so it is not quietly turned into a tally.
func TestDenyRequestIsFinalNotAVote(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob, arCarol)

	if w := f.denyAs(id, arBob); w.Code != http.StatusOK {
		t.Fatalf("denial returned %d", w.Code)
	}
	if got := f.requestStatus(id); got != "denied" {
		t.Fatalf("one denial left the request at %q, want denied", got)
	}
}

// THE ONE THAT MATTERS. A denied request must stay denied.
//
// handleApproveRequest reads the request only to compare requester_id against
// the caller; it never looks at the request's STATUS. The pending-count that
// decides whether to fulfil counts rows with decision='pending' and is blind to
// rows that say 'denied'. So after Bob denies, Carol's row is still pending,
// Carol approves, the count reaches zero, and the request is flipped back to
// approved and FULFILLED -- the role is granted over the top of a recorded
// refusal, and the audit trail holds both decisions with no sign that one
// overrode the other.
//
// That is the Deny button displaying a decision the product does not enforce.
func TestApproveCannotResurrectADeniedRequest(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.request("role", arRole, arBob, arCarol)

	if w := f.denyAs(id, arBob); w.Code != http.StatusOK {
		t.Fatalf("denial returned %d: %s", w.Code, w.Body.String())
	}

	w := f.approveAs(id, arCarol)
	if w.Code != http.StatusConflict {
		t.Errorf("approving after a denial returned %d (%s), want 409: a recorded refusal was overturned",
			w.Code, w.Body.String())
	}
	if got := f.requestStatus(id); got != "denied" {
		t.Errorf("request status = %q after an approval on a denied request, want denied", got)
	}
	if f.holdsRole(arAlice, arRole) {
		t.Error("the role was granted for a request that had been denied")
	}
}

func TestCancelRequestIsTheRequestersAlone(t *testing.T) {
	f := newApprovalFixture(t)

	t.Run("the requester can cancel while it is pending", func(t *testing.T) {
		id := f.request("role", arRole, arBob)
		if w := f.cancelAs(id, arAlice); w.Code != http.StatusOK {
			t.Fatalf("status = %d; body %s", w.Code, w.Body.String())
		}
		if got := f.requestStatus(id); got != "cancelled" {
			t.Errorf("status = %q, want cancelled", got)
		}
	})

	t.Run("an approver cannot cancel someone else's request", func(t *testing.T) {
		id := f.request("role", arRole, arBob)
		if w := f.cancelAs(id, arBob); w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
		if got := f.requestStatus(id); got != "pending" {
			t.Errorf("a refused cancellation still moved the request to %q", got)
		}
	})

	t.Run("a decided request cannot be cancelled", func(t *testing.T) {
		id := f.request("role", arRole, arBob)
		if w := f.denyAs(id, arBob); w.Code != http.StatusOK {
			t.Fatalf("denial returned %d", w.Code)
		}
		w := f.cancelAs(id, arAlice)
		if w.Code != http.StatusBadRequest {
			t.Errorf("cancelling a denied request returned %d, want 400", w.Code)
		}
		if got := f.requestStatus(id); got != "denied" {
			t.Errorf("status = %q, want the denial to stand", got)
		}
	})

	t.Run("an unknown request is a 404, not a 500", func(t *testing.T) {
		w := f.cancelAs("deadbeef-0000-0000-0000-000000000000", arAlice)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})

	t.Run("cancelling requires a caller", func(t *testing.T) {
		id := f.request("role", arRole, arBob)
		if w := f.cancelAs(id, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})
}
