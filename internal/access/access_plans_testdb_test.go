package access

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

type plansHarness struct {
	*diagnoseHarness
	router *gin.Engine
	ada    string
	bo     string
}

func newPlansHarness(t *testing.T, slug string) *plansHarness {
	t.Helper()
	d, ada, bo := newDiagnoseHarness(t, slug)
	r := gin.New()
	api := r.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: d.orgID}))
		c.Set("user_id", ada)
		c.Next()
	})
	api.POST("/plans", d.svc.handleCreateAccessPlan)
	api.GET("/plans", d.svc.handleListAccessPlans)
	api.POST("/plans/:id/approve", d.svc.handleApproveAccessPlan)
	api.POST("/plans/:id/reject", d.svc.handleRejectAccessPlan)
	api.POST("/plans/:id/undo", d.svc.handleUndoAccessPlan)
	return &plansHarness{diagnoseHarness: d, router: r, ada: ada, bo: bo}
}

func (p *plansHarness) call(method, path string, body any) (int, map[string]any) {
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/access"+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.router.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// app adds an application of the organization; group adds a group with the given members.
func (p *plansHarness) app(name, kind string, enabled bool) string {
	var id string
	if err := p.pool.QueryRow(p.ctx(), `INSERT INTO applications (client_id, name, type, kind, enabled, org_id)
		VALUES ($1, $1, 'web', $2, $3, $4::uuid) RETURNING id::text`, p.orgID[:8]+"-"+name, kind, enabled, p.orgID).Scan(&id); err != nil {
		p.t.Fatal(err)
	}
	// The display name is the one the test asks by.
	p.exec(`UPDATE applications SET name = $2 WHERE id = $1::uuid`, id, name)
	return id
}

func (p *plansHarness) group(name string, members ...string) string {
	var id string
	if err := p.pool.QueryRow(p.ctx(), `INSERT INTO groups (name, org_id) VALUES ($1, $2::uuid) RETURNING id::text`, p.orgID[:8]+"-"+name, p.orgID).Scan(&id); err != nil {
		p.t.Fatal(err)
	}
	p.exec(`UPDATE groups SET name = $2 WHERE id = $1::uuid`, id, name)
	for _, m := range members {
		p.exec(`INSERT INTO group_memberships (user_id, group_id) VALUES ($1::uuid, $2::uuid)`, m, id)
	}
	return id
}

func (p *plansHarness) granted(group, app string) bool {
	return p.count(`SELECT COUNT(*) FROM group_application_assignments WHERE group_id = $1::uuid AND application_id = $2::uuid`, group, app) == 1
}

func (p *plansHarness) status(id string) (s string) {
	_ = p.pool.QueryRow(p.ctx(), `SELECT status FROM agentic_proposals WHERE id = $1::uuid`, id).Scan(&s)
	return
}

func (p *plansHarness) ctx() context.Context { return context.Background() }

func TestAccessPlanLifecycle(t *testing.T) {
	p := newPlansHarness(t, "plans-org")
	app := p.app("Wiki", "web", true)
	grp := p.group("Engineering", p.bo)

	// Laying a plan out changes nothing, and by name or by id is the same plan.
	code, view := p.call(http.MethodPost, "/plans", map[string]string{"resource": "wiki", "group": "engineering"})
	if code != http.StatusCreated || view["status"] != "pending" || view["id"] == nil {
		t.Fatalf("create: %d %v", code, view)
	}
	id := view["id"].(string)
	if p.granted(grp, app) {
		t.Fatal("proposing a plan granted access")
	}
	now, _ := view["now"].(map[string]any)
	if now["checked"] != true {
		t.Errorf("the plan did not check what a member can do today: %v", now)
	}
	if code2, again := p.call(http.MethodPost, "/plans", map[string]string{"resource": app, "group": grp}); code2 != http.StatusCreated || again["id"] != id {
		t.Errorf("the same plan asked by id made a second one: %d %v", code2, again["id"])
	}
	if code, list := p.call(http.MethodGet, "/plans", nil); code != http.StatusOK || len(list["plans"].([]any)) != 1 {
		t.Errorf("list: %d %v", code, list)
	}

	// Approving carries it out and checks the result.
	code, out := p.call(http.MethodPost, "/plans/"+id+"/approve", nil)
	if code != http.StatusOK || out["granted"] != true || !p.granted(grp, app) || p.status(id) != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	after, _ := out["after"].(map[string]any)
	if after["checked"] != true || after["allowed"] != true {
		t.Errorf("after the grant a member should be allowed: %v", after)
	}
	if code, _ := p.call(http.MethodPost, "/plans/"+id+"/approve", nil); code != http.StatusNotFound {
		t.Errorf("approving twice answered %d, want 404", code)
	}

	// A plan for what is already granted is nothing to do, and is not stored.
	if code, v := p.call(http.MethodPost, "/plans", map[string]string{"resource": "Wiki", "group": "Engineering"}); code != http.StatusOK || v["status"] != "noop" {
		t.Errorf("already granted: %d %v", code, v)
	}

	// Undo takes back exactly that assignment.
	if code, _ := p.call(http.MethodPost, "/plans/"+id+"/undo", nil); code != http.StatusOK || p.granted(grp, app) || p.status(id) != "undone" {
		t.Errorf("undo did not take the access back (status %s)", p.status(id))
	}
	if code, _ := p.call(http.MethodPost, "/plans/"+id+"/undo", nil); code != http.StatusNotFound {
		t.Errorf("undoing twice answered %d, want 404", code)
	}
}

func TestAccessPlanBlockedStaleRejectedAndRisky(t *testing.T) {
	p := newPlansHarness(t, "plans-edge-org")
	app := p.app("Payroll", "privileged", true)
	p.app("Old", "web", false)
	grp := p.group("Empty")

	// Blocked: nothing stored.
	for name, body := range map[string]map[string]string{
		"no such resource":    {"resource": "nope", "group": "Empty"},
		"no such group":       {"resource": "Payroll", "group": "nope"},
		"a disabled resource": {"resource": "Old", "group": "Empty"},
	} {
		if code, v := p.call(http.MethodPost, "/plans", body); code != http.StatusUnprocessableEntity || v["status"] != "blocked" {
			t.Errorf("%s: %d %v", name, code, v)
		}
	}
	if n := p.count(`SELECT COUNT(*) FROM agentic_proposals WHERE kind = 'access_open'`); n != 0 {
		t.Errorf("%d blocked plans were stored", n)
	}
	if code, _ := p.call(http.MethodPost, "/plans", map[string]string{"resource": "", "group": "x"}); code != http.StatusBadRequest {
		t.Errorf("an empty resource answered %d", code)
	}

	// Risks are shown, not hidden: an empty group and a privileged resource.
	code, view := p.call(http.MethodPost, "/plans", map[string]string{"resource": "Payroll", "group": "Empty"})
	plan, _ := view["plan"].(map[string]any)
	risks, _ := plan["risks"].([]any)
	if code != http.StatusCreated || len(risks) != 2 {
		t.Fatalf("risky plan: %d %v", code, view)
	}
	id := view["id"].(string)
	if now, _ := view["now"].(map[string]any); now["checked"] != false {
		t.Errorf("an empty group has nobody to check with, and must say so: %v", now)
	}

	// The resource is switched off after the plan was made: approving is stale.
	p.exec(`UPDATE applications SET enabled = FALSE WHERE id = $1::uuid`, app)
	if code, _ := p.call(http.MethodPost, "/plans/"+id+"/approve", nil); code != http.StatusConflict || p.granted(grp, app) || p.status(id) != "superseded" {
		t.Errorf("a stale approval: %d granted=%v status=%s", code, p.granted(grp, app), p.status(id))
	}

	// Reject.
	p.exec(`UPDATE applications SET enabled = TRUE WHERE id = $1::uuid`, app)
	_, view = p.call(http.MethodPost, "/plans", map[string]string{"resource": "Payroll", "group": "Empty"})
	id = view["id"].(string)
	if code, _ := p.call(http.MethodPost, "/plans/"+id+"/reject", nil); code != http.StatusOK || p.status(id) != "rejected" || p.granted(grp, app) {
		t.Error("reject did not reject")
	}
}

func TestAccessPlansDoNotCrossOrganizations(t *testing.T) {
	p := newPlansHarness(t, "plans-iso-org")
	var other string
	_ = p.pool.QueryRow(p.ctx(), `INSERT INTO organizations (name, slug) VALUES ('plans-other', 'plans-other') RETURNING id::text`).Scan(&other)
	p.exec(`INSERT INTO applications (client_id, name, type, enabled, org_id) VALUES ('other-app', 'Secret', 'web', true, $1::uuid)`, other)
	p.group("Mine")
	if code, v := p.call(http.MethodPost, "/plans", map[string]string{"resource": "Secret", "group": "Mine"}); code != http.StatusUnprocessableEntity || v["status"] != "blocked" {
		t.Errorf("another organization's application was planned: %d %v", code, v)
	}
	var theirs string
	_ = p.pool.QueryRow(p.ctx(), `INSERT INTO agentic_proposals (org_id, kind, params, base_hash, target_id) VALUES ($1::uuid, 'access_open', '{}', 'x', 't') RETURNING id::text`, other).Scan(&theirs)
	for _, op := range []string{"approve", "reject", "undo"} {
		if code, _ := p.call(http.MethodPost, "/plans/"+theirs+"/"+op, nil); code != http.StatusNotFound {
			t.Errorf("%s of another organization's plan answered %d, want 404", op, code)
		}
	}
}
