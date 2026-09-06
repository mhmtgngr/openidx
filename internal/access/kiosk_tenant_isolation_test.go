package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the kiosk lockdown policies, migration v159.
//
// A kiosk_policies row puts a managed device into single-app or multi-app lock
// task mode: which packages may run, which activity is pinned to the screen,
// the branding shown, and the hash of the PIN required to leave. v44 created it
// with no tenant column, and the admin list carried the finding in its own doc
// comment — "HandleListPolicies returns every kiosk policy (admin view, no
// filtering)". Get, update and delete addressed a policy by bare id.
//
// The assignment is the sharper half: HandleAssignPolicy took the policy id
// from the URL and target_id from the body, checked neither, and wrote the row.
// So one administrator could aim ANOTHER tenant's lockdown policy — and its
// exit PIN — at a device.
func TestKioskPolicy_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('kiosk-b','kiosk-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	h := NewKioskAPIHandler(zaptest.NewLogger(t), db, nil)

	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("roles", []string{"admin"})
		handler(c)
		return w
	}

	createPolicy := func(org, name string) string {
		t.Helper()
		w := call(h.HandleCreatePolicy, org, "POST", "/kiosk/policies",
			fmt.Sprintf(`{"name":%q,"mode":"single_app","primary_activity":"com.example/.Main","exit_pin":"4242"}`, name),
			nil)
		if w.Code != 201 {
			t.Fatalf("create policy %s: status %d, body %s", name, w.Code, w.Body.String())
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		return out.ID
	}

	policyA := createPolicy(orgA, "kiosk-a-"+suffix)
	policyB := createPolicy(orgB, "kiosk-b-"+suffix)

	t.Run("the list is this organization's estate, not the installation's", func(t *testing.T) {
		list := func(org string) []kioskPolicyRow {
			t.Helper()
			w := call(h.HandleListPolicies, org, "GET", "/kiosk/policies", "", nil)
			if w.Code != 200 {
				t.Fatalf("list as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var out []kioskPolicyRow
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return out
		}
		gotA, gotB := list(orgA), list(orgB)
		if len(gotA) != 1 || gotA[0].ID != policyA {
			t.Errorf("org A's list is %d policies, want exactly its own. The handler's "+
				"own doc comment said it returns every kiosk policy with no "+
				"filtering, so one tenant's administrator saw another tenant's "+
				"device lockdown estate", len(gotA))
		}
		if len(gotB) != 1 || gotB[0].ID != policyB {
			t.Errorf("org B's list is %d policies, want exactly its own", len(gotB))
		}
	})

	t.Run("a policy is not readable, editable or deletable across tenants", func(t *testing.T) {
		p := gin.Params{{Key: "id", Value: policyA}}

		if w := call(h.HandleGetPolicy, orgB, "GET", "/kiosk/policies/"+policyA, "", p); w.Code != 404 {
			t.Errorf("org B read org A's lockdown configuration: status %d, body %s", w.Code, w.Body.String())
		}
		// Disabling it is the interesting edit: the device stops being locked.
		if w := call(h.HandleUpdatePolicy, orgB, "PUT", "/kiosk/policies/"+policyA,
			`{"name":"hijacked","enabled":false}`, p); w.Code != 404 {
			t.Errorf("org B rewrote org A's kiosk policy: status %d, body %s", w.Code, w.Body.String())
		}
		if w := call(h.HandleDeletePolicy, orgB, "DELETE", "/kiosk/policies/"+policyA, "", p); w.Code != 404 {
			t.Errorf("org B deleted org A's kiosk policy: status %d, body %s", w.Code, w.Body.String())
		}

		// Still there, still enabled, still named what its owner called it.
		w := call(h.HandleGetPolicy, orgA, "GET", "/kiosk/policies/"+policyA, "", p)
		if w.Code != 200 {
			t.Fatalf("org A lost its own policy: status %d, body %s", w.Code, w.Body.String())
		}
		var rec kioskPolicyRow
		if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if !rec.Enabled || rec.Name != "kiosk-a-"+suffix {
			t.Errorf("org A's policy was changed: enabled=%v name=%q", rec.Enabled, rec.Name)
		}
		if !rec.HasExitPIN {
			t.Error("org A's exit PIN was cleared")
		}
	})

	t.Run("another tenant's policy cannot be aimed at a device", func(t *testing.T) {
		p := gin.Params{{Key: "id", Value: policyA}}
		w := call(h.HandleAssignPolicy, orgB, "POST", "/kiosk/policies/"+policyA+"/assignments",
			`{"target_kind":"agent","target_id":"agent-`+suffix+`"}`, p)
		if w.Code != 404 {
			t.Errorf("org B aimed org A's lockdown policy at a device: status %d, body %s. "+
				"The handler took the policy id from the URL and the target from "+
				"the body and checked neither, so the device would be pinned to "+
				"one activity behind an exit PIN only org A knows",
				w.Code, w.Body.String())
		}

		// The owner can still assign: the term must scope, not deny outright.
		own := call(h.HandleAssignPolicy, orgA, "POST", "/kiosk/policies/"+policyA+"/assignments",
			`{"target_kind":"agent","target_id":"agent-`+suffix+`"}`, p)
		if own.Code != 201 {
			t.Fatalf("org A could not assign its own policy: status %d, body %s", own.Code, own.Body.String())
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(own.Body.Bytes(), &created); err != nil {
			t.Fatalf("bad json: %v", err)
		}

		// And org B cannot see or remove the assignment.
		if w := call(h.HandleListAssignments, orgB, "GET", "/kiosk/policies/"+policyA+"/assignments", "", p); w.Code == 200 {
			var out []kioskPolicyAssignmentRow
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if len(out) != 0 {
				t.Errorf("org B listed %d of org A's assignments", len(out))
			}
		}
		unassign := gin.Params{{Key: "assignment_id", Value: created.ID}}
		if w := call(h.HandleUnassignPolicy, orgB, "DELETE", "/kiosk/assignments/"+created.ID, "", unassign); w.Code != 404 {
			t.Errorf("org B lifted the lockdown from org A's device: status %d, body %s", w.Code, w.Body.String())
		}

		// The agent path still resolves it. This read runs under
		// WithBypassRLS on purpose: /agent/config is called by a device with
		// no organization on its context, and under the belt an unscoped read
		// returns nothing — which the caller treats as "no policy applies" and
		// silently omits the lockdown.
		got, err := resolveEffectiveKioskPolicy(ctx, db, "agent-"+suffix)
		if err != nil {
			t.Fatalf("agent policy resolution failed: %v", err)
		}
		if got == nil || got.ID != policyA {
			t.Errorf("the agent's effective policy is %v, want org A's. Belting the "+
				"table without the bypass would silently unlock every managed "+
				"device on the next config poll", got)
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal", func(t *testing.T) {
		for name, handler := range map[string]gin.HandlerFunc{
			"list":   h.HandleListPolicies,
			"create": h.HandleCreatePolicy,
			"get":    h.HandleGetPolicy,
			"delete": h.HandleDeletePolicy,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/kiosk/policies",
				bytes.NewBufferString(`{"name":"no-org","mode":"single_app"}`)) // bare context
			c.Request.Header.Set("Content-Type", "application/json")
			c.Params = gin.Params{{Key: "id", Value: policyA}}
			handler(c)
			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}
	})

	// v44 created these for internal/admin/ai_policy_recommendations.go, which
	// commit 7f8d189e removed as a dead route. Nothing has read or written
	// either since, so v159 drops them rather than scoping a pair of tables
	// that no code can reach.
	t.Run("v44's two orphan tables are gone", func(t *testing.T) {
		for _, table := range []string{"compliance_gaps", "policy_recommendations"} {
			var reg *string
			if err := db.Pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, table).Scan(&reg); err != nil {
				t.Fatalf("to_regclass(%s): %v", table, err)
			}
			if reg != nil {
				t.Errorf("%s still exists; it has no reader and no writer in the tree", table)
			}
		}
	})
}
