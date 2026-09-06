package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the joiner/mover/leaver workflows, migration v154.
//
// A lifecycle_workflows row is a rule: on this event, run these actions against
// the user. The actions are assign_role, remove_role, assign_group,
// remove_group, enable_user, disable_user and revoke_sessions, and every one of
// them was already written with `AND org_id = $N`. The rule that names them was
// not scoped at all:
//
//	SELECT ... FROM lifecycle_workflows                       -- no predicate
//	SELECT ... FROM lifecycle_workflows WHERE id = $1
//	UPDATE lifecycle_workflows SET ... actions = $5 ... WHERE id = $11
//	DELETE FROM lifecycle_workflows WHERE id = $1
//	SELECT ... FROM lifecycle_executions WHERE id = $1
//
// `actions` is a field the UPDATE sets, so the same shape as the deprovisioning
// half: a rule another tenant can rewrite is a rule pointed by whoever edited
// it last. The execution log is the read side — it names the account each run
// acted on and what was done to it.
func TestLifecycleWorkflows_TenantIsolation(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('lcw-b','lcw-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	ctxA := orgctx.With(ctx, orgctx.Org{ID: orgA})
	ctxB := orgctx.With(ctx, orgctx.Org{ID: orgB})
	s := &Service{db: db, logger: zap.NewNop()}

	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	userA := seedUser(orgA, "lcw-a-user")
	userB := seedUser(orgB, "lcw-b-user")

	// Org A's leaver rule: on departure, revoke the sessions.
	wfA := &LifecycleWorkflow{
		Name:        "lcw-a-leaver-" + suffix,
		EventType:   "leaver",
		TriggerType: "manual",
		Actions:     []map[string]interface{}{{"type": "revoke_sessions"}},
		Enabled:     true,
	}
	if err := s.CreateLifecycleWorkflow(ctxA, wfA); err != nil {
		t.Fatalf("create org A workflow: %v", err)
	}

	// THE RE-AIM. `actions` is settable, so this is the same finding as the
	// de-provisioning half: another tenant turns a session revocation into an
	// account disable and the owner keeps running it.
	t.Run("another tenant cannot re-aim the rule", func(t *testing.T) {
		hostile := &LifecycleWorkflow{
			ID:          wfA.ID,
			Name:        wfA.Name,
			EventType:   "leaver",
			TriggerType: "manual",
			Actions:     []map[string]interface{}{{"type": "disable_user"}},
			Enabled:     true,
		}
		if err := s.UpdateLifecycleWorkflow(ctxB, hostile); err == nil {
			t.Error("org B's update of org A's workflow succeeded; expected not-found")
		}

		got, err := s.GetLifecycleWorkflow(ctxA, wfA.ID)
		if err != nil {
			t.Fatalf("read back org A workflow: %v", err)
		}
		if len(got.Actions) != 1 || got.Actions[0]["type"] != "revoke_sessions" {
			t.Fatalf("org B rewrote org A's lifecycle rule; actions are now %v. "+
				"The owner runs what their console still calls a leaver workflow "+
				"and it does what another tenant chose", got.Actions)
		}
	})

	// THE REMOVAL.
	t.Run("another tenant cannot delete the rule", func(t *testing.T) {
		if err := s.DeleteLifecycleWorkflow(ctxB, wfA.ID); err == nil {
			t.Error("org B's delete of org A's workflow succeeded; expected not-found")
		}
		if _, err := s.GetLifecycleWorkflow(ctxA, wfA.ID); err != nil {
			t.Fatalf("org B deleted org A's lifecycle workflow: %v", err)
		}
	})

	// THE READ.
	t.Run("another tenant cannot get or list the rule", func(t *testing.T) {
		if _, err := s.GetLifecycleWorkflow(ctxB, wfA.ID); err == nil {
			t.Error("org B read org A's workflow by id")
		}

		wfB := &LifecycleWorkflow{
			Name:        "lcw-b-joiner-" + suffix,
			EventType:   "joiner",
			TriggerType: "manual",
			Actions:     []map[string]interface{}{{"type": "enable_user"}},
			Enabled:     true,
		}
		if err := s.CreateLifecycleWorkflow(ctxB, wfB); err != nil {
			t.Fatalf("create org B workflow: %v", err)
		}

		names := func(c context.Context, who string) map[string]bool {
			t.Helper()
			list, _, err := s.ListLifecycleWorkflows(c, 0, 100, "")
			if err != nil {
				t.Fatalf("list as %s: %v", who, err)
			}
			out := map[string]bool{}
			for _, w := range list {
				out[w.Name] = true
			}
			return out
		}
		gotA, gotB := names(ctxA, "A"), names(ctxB, "B")

		if gotB[wfA.Name] {
			t.Error("org B's workflow list included org A's rule")
		}
		if gotA[wfB.Name] {
			t.Error("org A's workflow list included org B's rule")
		}
		// The predicate must scope the read, not empty it.
		if !gotA[wfA.Name] {
			t.Error("org A's list lost org A's own workflow")
		}
		if !gotB[wfB.Name] {
			t.Error("org B's list lost org B's own workflow")
		}
	})

	// THE TARGET. Every action carries `AND org_id = $N`, so a foreign user id
	// matches nothing — and without this check the run would still write an
	// execution row reading "completed" with every action under
	// actions_completed. Refusing is the only honest answer.
	t.Run("a run against another tenant's user is refused, not reported complete", func(t *testing.T) {
		if _, err := s.ExecuteLifecycleWorkflow(ctxA, wfA.ID, userB, userA); err == nil {
			t.Fatal("org A ran its leaver workflow against an org B account and the " +
				"call succeeded. Every action is scoped by org, so nothing would " +
				"have happened — and the execution row would have said 'completed' " +
				"with the action listed as done. A lifecycle run that reports " +
				"success having touched no account is exactly the failure this " +
				"subsystem was fixed for once already")
		}

		var rows int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM lifecycle_executions WHERE workflow_id = $1::uuid`,
			wfA.ID).Scan(&rows); err != nil {
			t.Fatalf("count executions: %v", err)
		}
		if rows != 0 {
			t.Fatalf("the refused run still wrote %d execution row(s); the refusal has "+
				"to come before the record, or the log claims work that never happened", rows)
		}
	})

	// THE RUN LOG. A real run, then the cross-tenant read of it.
	t.Run("another tenant cannot read the run log", func(t *testing.T) {
		ex, err := s.ExecuteLifecycleWorkflow(ctxA, wfA.ID, userA, userA)
		if err != nil {
			t.Fatalf("org A's own run of its own workflow failed: %v", err)
		}

		if _, err := s.GetLifecycleExecution(ctxB, ex.ID); err == nil {
			t.Error("org B read org A's lifecycle execution by id. The row names the " +
				"account the run acted on and what was done to it")
		}
		if _, err := s.GetLifecycleExecution(ctxA, ex.ID); err != nil {
			t.Errorf("org A could not read its own execution: %v", err)
		}

		list, total, err := s.ListLifecycleExecutions(ctxB, 0, 100, "", "")
		if err != nil {
			t.Fatalf("list executions as org B: %v", err)
		}
		for _, e := range list {
			if e.ID == ex.ID {
				t.Fatalf("org A's execution appeared in org B's list (total reported %d)", total)
			}
		}
	})

	// The direction of a failure.
	t.Run("no organization is an error, not an unfiltered read", func(t *testing.T) {
		if _, _, err := s.ListLifecycleWorkflows(ctx, 0, 100, ""); err == nil {
			t.Error("ListLifecycleWorkflows returned rows for a context with no organization")
		}
		if _, _, err := s.ListLifecycleExecutions(ctx, 0, 100, "", ""); err == nil {
			t.Error("ListLifecycleExecutions returned rows for a context with no organization")
		}
		if err := s.CreateLifecycleWorkflow(ctx, &LifecycleWorkflow{
			Name: "lcw-orphan-" + suffix, EventType: "joiner", TriggerType: "manual",
		}); err == nil {
			t.Error("CreateLifecycleWorkflow wrote a rule with no organization; a row that " +
				"names no tenant is the state this migration exists to make impossible")
		}
	})
}
