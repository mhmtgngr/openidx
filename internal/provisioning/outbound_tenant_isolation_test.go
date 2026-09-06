package provisioning

import (
	"context"
	"net/http"
	"testing"

	"go.uber.org/zap"
)

// Tenant isolation for the outbound SCIM surface, migration v164.
//
// v95's registry description says, in full, "Org-scoped for RLS." Each of its
// three tables got an org_id column; none got FORCE ROW LEVEL SECURITY, a
// policy, a NOT NULL, or a foreign key. And every "org-scoped" query in the
// store carried its own escape hatch:
//
//	WHERE id = $1 AND (org_id::text = $2 OR $2 = '')
//
// An empty organization meant EVERY organization. Reached with "",
// ListTargetApps returned every tenant's SCIM connections, DeleteTargetApp
// removed any of them (with their records and queued operations, by cascade),
// and EnqueueFullSync pushed the whole installation's directory into one
// tenant's downstream SaaS.
//
// Nothing reached it through the mounted routes -- TenantResolver runs in front
// of every one of them and either attaches an organization or aborts -- and the
// only callers in the tree that passed "" were this package's own tests. These
// cases pin both halves: the wildcard is gone, and a request without an
// organization is refused rather than treated as one.
func TestOutboundSCIM_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const orgB = "00000000-0000-0000-0000-0000000000ba"
	svc := &Service{db: db, logger: zap.NewNop()}

	targetA, err := svc.CreateTargetApp(ctx, testOrgID, &TargetAppInput{
		Name: "org-a-slack", BaseURL: "https://a.example.test/scim/v2", AuthType: "bearer",
		BearerToken: "xoxb-org-a-secret", ProvisionUsers: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create org A target: %v", err)
	}
	if _, err := svc.CreateTargetApp(ctx, orgB, &TargetAppInput{
		Name: "org-b-okta", BaseURL: "https://b.example.test/scim/v2", AuthType: "bearer",
		BearerToken: "okta-org-b-secret", ProvisionUsers: true, Enabled: true,
	}); err != nil {
		t.Fatalf("create org B target: %v", err)
	}

	t.Run("a target is created with a real tenant, never NULL", func(t *testing.T) {
		var nulls int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM scim_target_apps WHERE org_id IS NULL`).Scan(&nulls); err != nil {
			t.Fatalf("count: %v", err)
		}
		if nulls != 0 {
			t.Errorf("%d target apps were stored with a NULL organization. The insert "+
				"passed the org through nullIfEmpty, and a NULL-org row is invisible "+
				"to every org-scoped read once the belt lands -- the connection keeps "+
				"provisioning and stops appearing on the console", nulls)
		}
	})

	t.Run("the list is this tenant's connections, not the installation's", func(t *testing.T) {
		got, err := svc.ListTargetApps(ctx, testOrgID)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].Name != "org-a-slack" {
			t.Errorf("org A sees %d SCIM connections, want exactly its own", len(got))
		}

		// The wildcard: an absent organization used to mean every organization.
		wide, err := svc.ListTargetApps(ctx, "")
		if err != nil {
			t.Fatalf("list with no org: %v", err)
		}
		if len(wide) != 0 {
			t.Errorf("an empty organization returned %d SCIM connections. The predicate "+
				"was `WHERE (org_id::text = $1 OR $1 = '')`, so an absent tenant "+
				"meant every tenant -- base URLs, OAuth client ids and sync state "+
				"for the whole installation", len(wide))
		}
	})

	t.Run("another tenant's connection cannot be read, rewritten or deleted", func(t *testing.T) {
		if _, err := svc.GetTargetApp(ctx, orgB, targetA.ID); err == nil {
			t.Error("org B read org A's SCIM connection")
		}
		// Rewriting base_url is the sharp edge: it is where the provisioning
		// goes, and the credential travels with it.
		if _, err := svc.UpdateTargetApp(ctx, orgB, targetA.ID, &TargetAppInput{
			BaseURL: "https://attacker.example.test/scim/v2", Enabled: true,
		}); err == nil {
			t.Error("org B repointed org A's provisioning at another server")
		}
		if err := svc.DeleteTargetApp(ctx, orgB, targetA.ID); err == nil {
			t.Error("org B deleted org A's SCIM connection, and its records and queue with it")
		}

		// Untouched, and still pointing where its owner put it.
		back, err := svc.GetTargetApp(ctx, testOrgID, targetA.ID)
		if err != nil {
			t.Fatalf("org A lost its own connection: %v", err)
		}
		if back.BaseURL != "https://a.example.test/scim/v2" {
			t.Errorf("org A's connection now points at %q", back.BaseURL)
		}
	})

	t.Run("the downstream credential is not readable by id alone", func(t *testing.T) {
		tok, err := svc.bearerTokenFor(ctx, testOrgID, targetA.ID)
		if err != nil || tok != "xoxb-org-a-secret" {
			t.Fatalf("org A could not read its own token: %q %v", tok, err)
		}
		if _, err := svc.bearerTokenFor(ctx, orgB, targetA.ID); err == nil {
			t.Error("org B read the decrypted admin credential for org A's downstream SaaS")
		}
	})

	t.Run("the fan-out reaches only this tenant's targets", func(t *testing.T) {
		const userID = "00000000-0000-0000-0000-0000000000c1"
		n, err := svc.EnqueueUserOp(ctx, testOrgID, userID, OpCreate,
			userSnapshot{ID: userID, UserName: "a@a.test", Active: true})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if n != 1 {
			t.Errorf("a user change fanned out to %d targets, want org A's one", n)
		}

		// And the outbox row carries its tenant, so the belt can scope it.
		var orgs []string
		rows, err := db.Pool.Query(ctx,
			`SELECT COALESCE(org_id::text,'<null>') FROM scim_provisioning_queue`)
		if err != nil {
			t.Fatalf("read queue: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var o string
			if err := rows.Scan(&o); err != nil {
				t.Fatal(err)
			}
			orgs = append(orgs, o)
		}
		for _, o := range orgs {
			if o != testOrgID {
				t.Errorf("an outbox row carries organization %q; the enqueue wrote its "+
					"tenant through nullIfEmpty, so an absent org produced a row no "+
					"operator could see", o)
			}
		}
	})

	t.Run("the per-target counts are this tenant's", func(t *testing.T) {
		rep, err := svc.TargetStatus(ctx, testOrgID, targetA.ID)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if rep.QueueByState["pending"] != 1 {
			t.Errorf("org A's target reports %v queued, want one pending", rep.QueueByState)
		}
		other, err := svc.TargetStatus(ctx, orgB, targetA.ID)
		if err != nil {
			t.Fatalf("status as org B: %v", err)
		}
		if len(other.QueueByState) != 0 {
			t.Errorf("org B read org A's provisioning backlog: %v", other.QueueByState)
		}
	})

	// The direction of a failure. TenantResolver makes this unreachable on the
	// mounted routes; the handlers no longer depend on that being true.
	t.Run("no organization is a refusal, not a wildcard", func(t *testing.T) {
		r := newOutboundTestRouterAs(svc, "")
		for _, tc := range []struct {
			method, path string
			body         interface{}
		}{
			{http.MethodGet, "/api/v1/provisioning/targets", nil},
			{http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{Name: "x", BaseURL: "https://x/scim"}},
			{http.MethodGet, "/api/v1/provisioning/targets/" + targetA.ID, nil},
			{http.MethodDelete, "/api/v1/provisioning/targets/" + targetA.ID, nil},
			{http.MethodPost, "/api/v1/provisioning/targets/" + targetA.ID + "/sync", nil},
			{http.MethodGet, "/api/v1/provisioning/targets/" + targetA.ID + "/status", nil},
		} {
			w := doJSON(t, r, tc.method, tc.path, tc.body)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with no organization returned %d, expected 403: %s",
					tc.method, tc.path, w.Code, w.Body.String())
			}
		}

		// Still there: the refusals did not delete or sync anything.
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM scim_target_apps`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Errorf("%d SCIM connections remain, want both", n)
		}
	})

	// EnqueueFullSync is the one that reads the directory. With no organization
	// it used to select every user on the installation into one tenant's outbox.
	t.Run("a full sync enqueues this tenant's directory only", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS users (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
				username VARCHAR(255), email VARCHAR(255),
				first_name VARCHAR(255), last_name VARCHAR(255), enabled BOOLEAN DEFAULT true)`); err != nil {
			t.Fatalf("users schema: %v", err)
		}
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO users (org_id, username, email) VALUES
				($1::uuid, 'a-one', 'a-one@a.test'),
				($2::uuid, 'b-one', 'b-one@b.test'),
				($2::uuid, 'b-two', 'b-two@b.test')`, testOrgID, orgB); err != nil {
			t.Fatalf("seed users: %v", err)
		}

		target, err := svc.GetTargetApp(ctx, testOrgID, targetA.ID)
		if err != nil {
			t.Fatalf("load target: %v", err)
		}
		n, err := svc.EnqueueFullSync(ctx, testOrgID, target)
		if err != nil {
			t.Fatalf("full sync: %v", err)
		}
		if n != 1 {
			t.Errorf("a full sync of org A's target enqueued %d users; org A has one and "+
				"the installation has three. The select was `FROM users u WHERE "+
				"(u.org_id::text = $3 OR $3 = '')`, so an absent organization pushed "+
				"every tenant's username, email and name into one tenant's "+
				"downstream SaaS", n)
		}
		// And the payloads name nobody from org B.
		var leaked int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM scim_provisioning_queue
			  WHERE payload->>'user_name' LIKE 'b-%'`).Scan(&leaked); err != nil {
			t.Fatalf("scan payloads: %v", err)
		}
		if leaked != 0 {
			t.Errorf("%d outbox payloads carry org B's directory entries", leaked)
		}
	})
}
