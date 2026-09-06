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

// Tenant isolation for the notification admin surface, migration v160.
//
// Three tables, all v54's, none with a tenant column.
//
// email_templates carries the seventh install-wide unique key this programme
// has found: `slug VARCHAR(100) UNIQUE NOT NULL`, so one organization naming a
// template 'welcome' owns that slug for the whole installation. All five
// template handlers addressed rows without naming an organization — while two
// functions below them, handleGetEmailBranding has resolved the caller's
// organization since v140.
//
// broadcast_messages is the sharper one. handleSendBroadcast resolves the
// caller's organization to pick recipients, and then loaded the message itself
// by bare id, so one administrator could take another organization's unsent
// draft and deliver it, under their own tenancy, to their own users.
//
// notification_routing_rules decides which channels an event reaches.
func TestNotificationAdmin_TenantIsolation(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('notif-b','notif-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	s := &Service{db: db, logger: zap.NewNop()}

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

	// THE SEVENTH INSTALL-WIDE KEY. Both organizations use the same slug; before
	// v160 the second insert died on email_templates_slug_key.
	t.Run("two organizations can hold a template with the same slug", func(t *testing.T) {
		seed := func(org, subject string) string {
			t.Helper()
			var id string
			if err := db.Pool.QueryRow(ctx, `
				INSERT INTO email_templates (name, slug, subject, html_body, org_id)
				VALUES ($1, $2, $3, '<p>hi</p>', $4::uuid) RETURNING id::text`,
				"Welcome "+org, "welcome-"+suffix, subject, org).Scan(&id); err != nil {
				t.Fatalf("seed template for %s: %v. v54 declared slug UNIQUE across "+
					"the installation, so the first organization to name a template "+
					"owned that name for everyone", org, err)
			}
			return id
		}
		templateA := seed(orgA, "Welcome to A")
		seed(orgB, "Welcome to B")

		// The list is one organization's.
		w := call(s.handleListEmailTemplates, orgA, "GET", "/email-templates", "", nil)
		if w.Code != 200 {
			t.Fatalf("list as org A: status %d, body %s", w.Code, w.Body.String())
		}
		var listed struct {
			Data []EmailTemplate `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		// org A also holds v129's starter templates: they carry no author, so
		// v160's backfill puts them in the oldest organization. What must not
		// appear is org B's.
		var sawA, sawB bool
		for _, tpl := range listed.Data {
			switch tpl.Subject {
			case "Welcome to A":
				sawA = true
			case "Welcome to B":
				sawB = true
			}
		}
		if !sawA {
			t.Errorf("org A's own template is missing from its list (%d entries)", len(listed.Data))
		}
		if sawB {
			t.Error("org A's template list contains org B's. Every administrator on " +
				"the installation saw and could rewrite one shared set of templates " +
				"-- the subject and body of the mail the product sends about " +
				"passwords, invitations and one-time codes")
		}

		// And org B's list must not contain org A's, nor v129's starters: an
		// organization created after the upgrade begins with none.
		wb := call(s.handleListEmailTemplates, orgB, "GET", "/email-templates", "", nil)
		var listedB struct {
			Data []EmailTemplate `json:"data"`
		}
		if err := json.Unmarshal(wb.Body.Bytes(), &listedB); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if len(listedB.Data) != 1 || listedB.Data[0].Subject != "Welcome to B" {
			t.Errorf("org B's list is %d entries, want exactly its own", len(listedB.Data))
		}

		// And org B cannot read or rewrite org A's.
		p := gin.Params{{Key: "id", Value: templateA}}
		if w := call(s.handleGetEmailTemplate, orgB, "GET", "/email-templates/"+templateA, "", p); w.Code != 404 {
			t.Errorf("org B read org A's template: status %d", w.Code)
		}
		if w := call(s.handleUpdateEmailTemplate, orgB, "PUT", "/email-templates/"+templateA,
			`{"subject":"Rewritten by B"}`, p); w.Code != 404 {
			t.Errorf("org B rewrote org A's template: status %d, body %s", w.Code, w.Body.String())
		}
		var subject string
		if err := db.Pool.QueryRow(ctx,
			`SELECT subject FROM email_templates WHERE id = $1::uuid`, templateA).Scan(&subject); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if subject != "Welcome to A" {
			t.Errorf("org A's template subject is now %q", subject)
		}
	})

	// A DRAFT ANOTHER TENANT COULD SEND.
	t.Run("a broadcast draft is not readable or sendable across tenants", func(t *testing.T) {
		create := func(org, title string) string {
			t.Helper()
			w := call(s.handleCreateBroadcast, org, "POST", "/broadcasts",
				fmt.Sprintf(`{"title":%q,"body":"body","channel":"in_app","target_type":"all"}`, title), nil)
			if w.Code != 201 {
				t.Fatalf("create broadcast for %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var b BroadcastMessage
			if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return b.ID
		}
		draftA := create(orgA, "org A announcement "+suffix)
		create(orgB, "org B announcement "+suffix)

		w := call(s.handleListBroadcasts, orgA, "GET", "/broadcasts", "", nil)
		if w.Code != 200 {
			t.Fatalf("list as org A: status %d, body %s", w.Code, w.Body.String())
		}
		var listed struct {
			Data []BroadcastMessage `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &listed)
		if n := len(listed.Data); n > 1 {
			t.Errorf("org A's broadcast list has %d entries, want its own only", n)
		}

		p := gin.Params{{Key: "id", Value: draftA}}
		if w := call(s.handleGetBroadcast, orgB, "GET", "/broadcasts/"+draftA, "", p); w.Code != 404 {
			t.Errorf("org B read org A's draft: status %d", w.Code)
		}
		// The one that matters: sending it.
		if w := call(s.handleSendBroadcast, orgB, "POST", "/broadcasts/"+draftA+"/send", "", p); w.Code == 200 {
			t.Error("org B sent org A's unsent draft to org B's users. handleSendBroadcast " +
				"resolved the organization for the RECIPIENTS and loaded the message " +
				"itself by bare id")
		}
		// Deleting a draft removes an announcement with no trace.
		if w := call(s.handleDeleteBroadcast, orgB, "DELETE", "/broadcasts/"+draftA, "", p); w.Code == 200 {
			t.Error("org B deleted org A's draft broadcast")
		}
		var status string
		if err := db.Pool.QueryRow(ctx,
			`SELECT status FROM broadcast_messages WHERE id = $1::uuid`, draftA).Scan(&status); err != nil {
			t.Fatalf("org A's draft is gone: %v", err)
		}
		if status != "draft" {
			t.Errorf("org A's draft is now %q", status)
		}
	})

	// The rule that decides which channel an alert reaches.
	t.Run("a routing rule cannot be re-aimed or deleted from another tenant", func(t *testing.T) {
		w := call(s.handleCreateRoutingRule, orgA, "POST", "/routing-rules",
			fmt.Sprintf(`{"name":"alerts-%s","event_type":"security_alert","channels":["in_app","email"],"priority":1}`, suffix), nil)
		if w.Code != 201 {
			t.Fatalf("create rule: status %d, body %s", w.Code, w.Body.String())
		}
		var rule NotificationRoutingRule
		if err := json.Unmarshal(w.Body.Bytes(), &rule); err != nil {
			t.Fatalf("bad json: %v", err)
		}

		p := gin.Params{{Key: "id", Value: rule.ID}}
		if w := call(s.handleGetRoutingRule, orgB, "GET", "/routing-rules/"+rule.ID, "", p); w.Code != 404 {
			t.Errorf("org B read org A's routing rule: status %d", w.Code)
		}
		// Dropping email from a security-alert rule is the interesting edit.
		if w := call(s.handleUpdateRoutingRule, orgB, "PUT", "/routing-rules/"+rule.ID,
			`{"channels":["in_app"]}`, p); w.Code == 200 {
			t.Error("org B switched org A's security-alert rule off email; org A's " +
				"alerts would stop arriving by mail with nothing on screen to say so")
		}
		if w := call(s.handleDeleteRoutingRule, orgB, "DELETE", "/routing-rules/"+rule.ID, "", p); w.Code == 200 {
			t.Error("org B deleted org A's routing rule")
		}

		var channels []byte
		if err := db.Pool.QueryRow(ctx,
			`SELECT channels FROM notification_routing_rules WHERE id = $1::uuid`, rule.ID).Scan(&channels); err != nil {
			t.Fatalf("org A's rule is gone: %v", err)
		}
		if !bytes.Contains(channels, []byte("email")) {
			t.Errorf("org A's rule channels are now %s", channels)
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal", func(t *testing.T) {
		for name, handler := range map[string]gin.HandlerFunc{
			"templates": s.handleListEmailTemplates,
			"rules":     s.handleListRoutingRules,
			"broadcast": s.handleListBroadcasts,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/notifications", nil) // bare context
			c.Set("roles", []string{"admin"})
			handler(c)
			if w.Code != 403 {
				t.Errorf("%s with no organization returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}
	})
}
