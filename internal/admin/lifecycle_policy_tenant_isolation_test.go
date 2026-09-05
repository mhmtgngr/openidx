package admin

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

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the de-provisioning policies, migration v154.
//
// A lifecycle_policies row is the rule that decides which accounts get
// disabled, deleted, or forced to change their password. Everything the rule
// DOES was already scoped — findAffectedUsers selects with `AND org_id = $N`,
// and the disable/delete/reset all carry the same term. What was not scoped is
// the rule itself:
//
//	SELECT ... FROM lifecycle_policies ORDER BY name
//	UPDATE lifecycle_policies SET %s WHERE id = $N
//	DELETE FROM lifecycle_policies WHERE id = $1
//	SELECT ... FROM lifecycle_policy_executions WHERE policy_id = $1
//
// The sharp one is the UPDATE, because `conditions` and `actions` are both
// fields it will SET. Another tenant could take a policy labelled "disable
// after 90 days", make it "delete after 0", and hand it back; the owner then
// runs their own rule and it empties their directory. The org predicate on the
// DELETE inside executeLifecyclePolicy does not help, because by then the rows
// being destroyed are the owner's own.
//
// The harness connects as the container superuser, which bypasses RLS, so what
// these prove is the explicit org predicate in every query. The FORCE RLS belt
// is proven separately in test/integration/cross_org_test.go under a
// NOSUPERUSER NOBYPASSRLS role.
func TestLifecyclePolicies_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
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
		`INSERT INTO organizations (name, slug) VALUES ('lcp-b','lcp-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	s := &Service{db: db, logger: zap.NewNop()}

	// A policy belonging to org A: disable an account after 90 idle days. The
	// values here are what the assertions read back, so a successful re-aim by
	// org B is visible as a change to them.
	var policyA string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO lifecycle_policies (name, policy_type, conditions, actions, enabled, org_id)
		VALUES ($1, 'stale_account_disable', '{"inactive_days": 90}'::jsonb,
		        '{"action": "disable"}'::jsonb, true, $2::uuid) RETURNING id::text`,
		"lcp-a-stale-"+suffix, orgA).Scan(&policyA); err != nil {
		t.Fatalf("seed org A policy: %v", err)
	}

	// A run of that policy, with the shape the real execution writes: the
	// affected account's username and the reason it was picked.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO lifecycle_policy_executions (policy_id, status, users_scanned, users_affected, actions_taken, org_id)
		VALUES ($1::uuid, 'completed', 1, 1,
		        '[{"user_id":"u1","username":"alice.in.org.a","action":"disable","reason":"No login for 90+ days"}]'::jsonb,
		        $2::uuid)`, policyA, orgA); err != nil {
		t.Fatalf("seed org A execution: %v", err)
	}

	// call drives one handler as an administrator of `org`.
	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", "00000000-0000-0000-0000-0000000000a1")
		c.Params = params
		handler(c)
		return w
	}

	readPolicyA := func() (conditions, actions string) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx,
			`SELECT conditions::text, actions::text FROM lifecycle_policies WHERE id = $1::uuid`,
			policyA).Scan(&conditions, &actions); err != nil {
			t.Fatalf("read back org A policy: %v", err)
		}
		return
	}

	// THE RE-AIM. This is the whole finding in one case.
	t.Run("another tenant cannot re-aim the rule", func(t *testing.T) {
		w := call(s.handleUpdateLifecyclePolicy, orgB, "PUT", "/lifecycle-policies/"+policyA,
			`{"conditions":{"inactive_days":0},"actions":{"action":"delete"}}`,
			gin.Params{{Key: "id", Value: policyA}})
		if w.Code == 200 {
			t.Errorf("org B's update of org A's policy returned 200; expected 404")
		}

		conds, acts := readPolicyA()
		if conds != `{"inactive_days": 90}` || acts != `{"action": "disable"}` {
			t.Fatalf("org B rewrote org A's de-provisioning rule: conditions=%s actions=%s. "+
				"The owner's next run of what their console still calls "+
				"\"Stale Account Auto-Disable\" would delete every account "+
				"that has been idle for zero days, which is all of them — "+
				"and the org predicate on the DELETE does not help, because "+
				"the rows destroyed are the owner's own", conds, acts)
		}
	})

	// THE REMOVAL. Losing a leaver control is quiet: nothing on the owner's
	// console says the rule that used to disable departed staff is gone.
	t.Run("another tenant cannot delete the rule", func(t *testing.T) {
		w := call(s.handleDeleteLifecyclePolicy, orgB, "DELETE", "/lifecycle-policies/"+policyA, "",
			gin.Params{{Key: "id", Value: policyA}})
		if w.Code == 200 {
			t.Errorf("org B's delete of org A's policy returned 200; expected 404")
		}

		var alive int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM lifecycle_policies WHERE id = $1::uuid`, policyA).Scan(&alive); err != nil {
			t.Fatalf("count: %v", err)
		}
		if alive != 1 {
			t.Fatal("org B deleted org A's de-provisioning policy. The offboarding " +
				"control stops existing and nothing on the owner's console says so")
		}
	})

	// THE RUN LOG. actions_taken names accounts and says what was done to each.
	t.Run("another tenant cannot read the run log", func(t *testing.T) {
		w := call(s.handleListLifecycleExecutions, orgB, "GET", "/lifecycle-policies/"+policyA+"/executions", "",
			gin.Params{{Key: "id", Value: policyA}})
		if w.Code != 200 {
			t.Fatalf("list executions as org B: status %d, body %s", w.Code, w.Body.String())
		}
		var resp struct {
			Data []LifecycleExecution `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(resp.Data) != 0 {
			t.Fatalf("org B read %d of org A's policy runs. actions_taken carries a "+
				"username and a reason per affected account, so this is org A's "+
				"directory with a justification column: %s", len(resp.Data), w.Body.String())
		}

		// And the owner must see it. Asserting only the empty answer above would
		// pass against a read that returns nothing to anyone -- which is what
		// this handler did, because error_message is NULL on every successful
		// run and the row was dropped on the scan.
		wa := call(s.handleListLifecycleExecutions, orgA, "GET", "/lifecycle-policies/"+policyA+"/executions", "",
			gin.Params{{Key: "id", Value: policyA}})
		if wa.Code != 200 {
			t.Fatalf("list executions as org A: status %d, body %s", wa.Code, wa.Body.String())
		}
		var own struct {
			Data []LifecycleExecution `json:"data"`
		}
		if err := json.Unmarshal(wa.Body.Bytes(), &own); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(own.Data) != 1 {
			t.Fatalf("org A saw %d runs of its own policy, expected 1. A completed run "+
				"has no error_message, so an uncoalesced scan drops it and the "+
				"history of a policy that just disabled accounts reads as empty",
				len(own.Data))
		}
	})

	// THE EXECUTION. Running another tenant's rule against your own users means
	// a rule one organization wrote governs another's accounts.
	t.Run("another tenant cannot execute the rule", func(t *testing.T) {
		w := call(s.handleExecuteLifecyclePolicy, orgB, "POST", "/lifecycle-policies/"+policyA+"/execute",
			`{"dry_run":true}`, gin.Params{{Key: "id", Value: policyA}})
		if w.Code != 404 {
			t.Fatalf("org B executed org A's policy: status %d, body %s. A rule one "+
				"organization authored must not govern another's accounts, even "+
				"when the accounts it reaches are the caller's own",
				w.Code, w.Body.String())
		}
	})

	// THE LISTING, and the other half of the finding: the predicate must scope
	// the read, not empty it.
	t.Run("the list shows this tenant's rules and only those", func(t *testing.T) {
		var policyB string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO lifecycle_policies (name, policy_type, conditions, actions, enabled, org_id)
			VALUES ($1, 'orphan_detection', '{}'::jsonb, '{"action": "flag"}'::jsonb, true, $2::uuid)
			RETURNING id::text`, "lcp-b-orphan-"+suffix, orgB).Scan(&policyB); err != nil {
			t.Fatalf("seed org B policy: %v", err)
		}

		names := func(org string) map[string]bool {
			t.Helper()
			w := call(s.handleListLifecyclePolicies, org, "GET", "/lifecycle-policies", "", nil)
			if w.Code != 200 {
				t.Fatalf("list as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var resp struct {
				Data []LifecyclePolicy `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			out := map[string]bool{}
			for _, p := range resp.Data {
				out[p.Name] = true
			}
			return out
		}

		gotA, gotB := names(orgA), names(orgB)
		if gotB["lcp-a-stale-"+suffix] {
			t.Error("org B's policy list included org A's rule")
		}
		if gotA["lcp-b-orphan-"+suffix] {
			t.Error("org A's policy list included org B's rule")
		}
		if !gotA["lcp-a-stale-"+suffix] {
			t.Error("org A's policy list lost org A's own rule: the org term must " +
				"scope this read, not empty it — an administrator who cannot see " +
				"their leaver policy cannot fix it either")
		}
		if !gotB["lcp-b-orphan-"+suffix] {
			t.Error("org B's policy list lost org B's own rule")
		}
	})

	// The direction of a failure: with no tenant to scope by there is no safe
	// unfiltered answer, because the unfiltered answer is every tenant's rules.
	t.Run("no organization is a refusal, not an unfiltered list", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/lifecycle-policies", nil) // bare context: no org
		c.Set("roles", []string{"admin"})
		s.handleListLifecyclePolicies(c)
		if w.Code != 403 {
			t.Fatalf("listing with no organization returned %d, body %s; expected 403",
				w.Code, w.Body.String())
		}
	})
}
