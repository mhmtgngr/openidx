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

// Tenant isolation for the bulk user operations, migration v161.
//
// A bulk operation is the console's "do this to these fifty accounts" control:
// enable, disable, DELETE, assign or remove a role, add to or remove from a
// group, force a password change.
//
// THE ACTIONS WERE SCOPED AND THE RECORD OF THEM WAS NOT. Every statement in
// executeBulkOperation carries `AND org_id = $N`, and the function opens with a
// comment recording an earlier fix in this same programme. But the list read
// `FROM bulk_operations ORDER BY created_at DESC LIMIT 50` with no predicate at
// all, and bulk_operation_items stores `entity_name` — the USERNAME the item
// acted on — so opening another organization's run returned their directory.
//
// Two behaviours are asserted here beyond isolation, because both are controls
// rather than missing features: Cancel must actually stop a run, and an action
// that matched no row must not be recorded as a success.
func TestBulkOperations_TenantIsolation(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('bulk-b','bulk-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
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
	userA := seedUser(orgA, "bulk-a-user")
	userB := seedUser(orgB, "bulk-b-user")

	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		c.Set("roles", []string{"admin"})
		c.Set("user_id", org)
		handler(c)
		return w
	}

	// Seed a run directly so the goroutine the create handler starts does not
	// race the assertions.
	seedRun := func(org, status string, userID string) string {
		t.Helper()
		var opID string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO bulk_operations (type, status, total_items, parameters, org_id)
			VALUES ('disable_users', $1, 1, '{}', $2::uuid) RETURNING id::text`,
			status, org).Scan(&opID); err != nil {
			t.Fatalf("seed run: %v", err)
		}
		var username string
		_ = db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id = $1::uuid`, userID).Scan(&username)
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO bulk_operation_items (operation_id, entity_id, entity_name, status, org_id)
			VALUES ($1::uuid, $2::uuid, $3, 'pending', $4::uuid)`,
			opID, userID, username, org); err != nil {
			t.Fatalf("seed item: %v", err)
		}
		return opID
	}

	runA := seedRun(orgA, "completed", userA)
	seedRun(orgB, "completed", userB)

	t.Run("the run list is this organization's, not the installation's", func(t *testing.T) {
		list := func(org string) []BulkOperation {
			t.Helper()
			w := call(s.handleListBulkOperations, org, "GET", "/bulk-operations", "", nil)
			if w.Code != 200 {
				t.Fatalf("list as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var out struct {
				Data []BulkOperation `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return out.Data
		}
		if got := list(orgA); len(got) != 1 || got[0].ID != runA {
			t.Errorf("org A's run list is %d entries, want exactly its own. The read was "+
				"`FROM bulk_operations ORDER BY created_at DESC LIMIT 50` with no "+
				"predicate, so one administrator saw every organization's bulk runs, "+
				"their type (\"delete_users\") and their parameters", len(got))
		}
		if got := list(orgB); len(got) != 1 || got[0].ID == runA {
			t.Errorf("org B's run list is wrong: %d entries", len(got))
		}
	})

	// entity_name is a username. This read is a directory extract.
	t.Run("another tenant's run does not return their directory", func(t *testing.T) {
		p := gin.Params{{Key: "id", Value: runA}}
		if w := call(s.handleGetBulkOperation, orgB, "GET", "/bulk-operations/"+runA, "", p); w.Code != 404 {
			t.Errorf("org B opened org A's run: status %d, body %s. bulk_operation_items "+
				"stores the username each item acted on, so this returns org A's "+
				"accounts with what was done to them", w.Code, w.Body.String())
		}
		// The owner still gets its own items.
		w := call(s.handleGetBulkOperation, orgA, "GET", "/bulk-operations/"+runA, "", p)
		if w.Code != 200 {
			t.Fatalf("org A lost its own run: status %d, body %s", w.Code, w.Body.String())
		}
		var out struct {
			Items []BulkOperationItem `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(out.Items) != 1 {
			t.Errorf("org A's own run returned %d items, want 1", len(out.Items))
		}
	})

	t.Run("another tenant cannot cancel a running import", func(t *testing.T) {
		running := seedRun(orgA, "running", userA)
		p := gin.Params{{Key: "id", Value: running}}
		if w := call(s.handleCancelBulkOperation, orgB, "POST", "/bulk-operations/"+running+"/cancel", "", p); w.Code != 404 {
			t.Errorf("org B cancelled org A's running import: status %d", w.Code)
		}
		var status string
		if err := db.Pool.QueryRow(ctx,
			`SELECT status FROM bulk_operations WHERE id = $1::uuid`, running).Scan(&status); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "running" {
			t.Errorf("org A's run is now %q", status)
		}
		// The owner still can.
		if w := call(s.handleCancelBulkOperation, orgA, "POST", "/bulk-operations/"+running+"/cancel", "", p); w.Code != 200 {
			t.Errorf("org A could not cancel its own run: status %d, body %s", w.Code, w.Body.String())
		}
	})

	// CANCEL WAS A LIE. The loop never read the status it sets, so a cancelled
	// bulk DELETE kept deleting -- and then overwrote 'cancelled' with
	// 'completed', leaving no sign the cancel had been ignored.
	t.Run("a cancelled run stops, and stays cancelled", func(t *testing.T) {
		victim := seedUser(orgA, "bulk-cancel-victim")
		opID := seedRun(orgA, "cancelled", victim)

		s.executeBulkOperation(orgA, opID, "disable_users", []string{victim}, json.RawMessage("{}"))

		var status string
		var processed int
		if err := db.Pool.QueryRow(ctx,
			`SELECT status, processed_items FROM bulk_operations WHERE id = $1::uuid`,
			opID).Scan(&status, &processed); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "cancelled" {
			t.Errorf("a cancelled run finished as %q. The final write was "+
				"`SET status = 'completed'` with no status predicate, so it erased "+
				"the cancel the administrator had just made", status)
		}
		if processed != 0 {
			t.Errorf("a cancelled run processed %d accounts", processed)
		}
		var enabled bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT enabled FROM users WHERE id = $1::uuid`, victim).Scan(&enabled); err != nil {
			t.Fatalf("read victim: %v", err)
		}
		if !enabled {
			t.Error("a cancelled bulk disable disabled the account anyway. Cancel set a " +
				"column the execution loop never read")
		}
	})

	// A SUCCESS THAT TOUCHED NOBODY.
	t.Run("an action that matched no account is an error, not a success", func(t *testing.T) {
		// userB is in org B; org A's run names it, so every statement's
		// `AND org_id = $2` matches nothing -- and returns no error.
		opID := seedRun(orgA, "running", userB)
		s.executeBulkOperation(orgA, opID, "disable_users", []string{userB}, json.RawMessage("{}"))

		var itemStatus, errMsg string
		if err := db.Pool.QueryRow(ctx, `
			SELECT status, COALESCE(error_message, '') FROM bulk_operation_items
			WHERE operation_id = $1::uuid`, opID).Scan(&itemStatus, &errMsg); err != nil {
			t.Fatalf("read item: %v", err)
		}
		if itemStatus != "error" {
			t.Errorf("an account outside the organization was recorded %q. The UPDATE "+
				"matched no row and returned no error, so a bulk disable over fifty "+
				"foreign ids reported fifty successes and changed nothing", itemStatus)
		}
		if errMsg == "" {
			t.Error("the failure was recorded with no reason")
		}
		var successCount, errorCount int
		if err := db.Pool.QueryRow(ctx,
			`SELECT success_count, error_count FROM bulk_operations WHERE id = $1::uuid`,
			opID).Scan(&successCount, &errorCount); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if successCount != 0 || errorCount != 1 {
			t.Errorf("the run reports %d successes and %d errors, want 0 and 1", successCount, errorCount)
		}
		// And org B's user is untouched.
		var enabled bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT enabled FROM users WHERE id = $1::uuid`, userB).Scan(&enabled); err != nil {
			t.Fatalf("read org B user: %v", err)
		}
		if !enabled {
			t.Error("org A's bulk disable reached org B's account")
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal", func(t *testing.T) {
		for name, handler := range map[string]gin.HandlerFunc{
			"list":   s.handleListBulkOperations,
			"get":    s.handleGetBulkOperation,
			"cancel": s.handleCancelBulkOperation,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/bulk-operations", nil) // bare context
			c.Params = gin.Params{{Key: "id", Value: runA}}
			c.Set("roles", []string{"admin"})
			handler(c)
			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}
	})
}
