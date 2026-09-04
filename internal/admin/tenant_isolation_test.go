package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Tenant isolation for the three table families migration v138 put under
// org_id: ISPM (rules / findings / scores), AI agents (+ credentials,
// permissions, activity) and AI recommendations (+ history).
//
// Before v138 none of them had an org_id and every handler in ispm.go,
// ai_agents.go and ai_recommendations.go addressed rows by bare id — so this
// file is the regression guard for cross-tenant read AND mutation: org B must
// never see, dismiss, remediate, update, delete, suspend, re-key or apply
// anything org A owns, and one org's scan must not delete another's findings
// or overwrite its daily score.
//
// The harness connects as the container superuser, which bypasses RLS, so
// what these tests prove is the explicit org predicate in every query (the
// thing tools/orgscope lints for). The RLS belt itself is proven separately by
// test/integration/cross_org_test.go under a NOSUPERUSER role.
//
// It also pins the second half of the v138 fix: the Rules page is no longer a
// display without an enforcement. The scan reads the org's rules — a disabled
// rule is skipped, an edited severity is what the finding carries, rule_id is
// stamped — and a rule for a check the engine cannot run reports
// implemented=false and refuses to be enabled.

type tenantFixture struct {
	t    *testing.T
	db   *database.PostgresDB
	s    *Service
	orgA string
	orgB string
}

func newTenantFixture(t *testing.T) (*tenantFixture, func()) {
	t.Helper()
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	f := &tenantFixture{t: t, db: db, s: &Service{db: db, logger: zap.NewNop()}}
	f.orgA = f.seedOrg("ti-a-" + suffix)
	f.orgB = f.seedOrg("ti-b-" + suffix)
	return f, func() {
		// ON DELETE CASCADE on every v138 FK takes the ISPM/AI rows with the
		// orgs. The v36 belt tables are RESTRICT (fk_<t>_org), so anything a
		// test wrote into one has to go first, children before parents.
		for _, tbl := range []string{"notifications", "user_sessions", "users"} {
			f.exec("DELETE FROM "+tbl+" WHERE org_id IN ($1, $2)", f.orgA, f.orgB)
		}
		f.exec("DELETE FROM organizations WHERE id IN ($1, $2)", f.orgA, f.orgB)
		cleanup()
	}
}

func (f *tenantFixture) bypass() context.Context {
	return orgctx.WithBypassRLS(context.Background())
}

func (f *tenantFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.bypass(), q, args...); err != nil {
		f.t.Fatalf("exec (%s): %v", q, err)
	}
}

func (f *tenantFixture) count(q string, args ...interface{}) int {
	f.t.Helper()
	var n int
	if err := f.db.Pool.QueryRow(f.bypass(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

func (f *tenantFixture) seedOrg(slug string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.bypass(),
		"INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id", slug).Scan(&id); err != nil {
		f.t.Fatalf("seed org %s: %v", slug, err)
	}
	return id
}

// seedStaleUser creates an enabled user in org with no login for 200 days —
// enough for the stale-account check and the stale-account recommendation.
func (f *tenantFixture) seedStaleUser(org, name string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO users (username, email, enabled, org_id, last_login_at)
		VALUES ($1::varchar, $1::varchar || '@ti.test', true, $2::uuid, NOW() - INTERVAL '200 days') RETURNING id`, name, org).Scan(&id); err != nil {
		f.t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// call invokes a gin handler as an admin of org, with optional :id / :permId
// params and a JSON body, and returns the recorder.
func (f *tenantFixture) call(org string, h gin.HandlerFunc, method, path string, params map[string]string, body interface{}) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	c.Request = httptest.NewRequest(method, path, rdr).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("roles", []string{"admin"})
	c.Set("user_id", "00000000-0000-0000-0000-000000000001")
	for k, v := range params {
		c.Params = append(c.Params, gin.Param{Key: k, Value: v})
	}
	h(c)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder, into interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
		t.Fatalf("bad json (%d): %s", w.Code, w.Body.String())
	}
}

func TestTenantIsolation_ISPMAndAI(t *testing.T) {
	f, cleanup := newTenantFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	t.Run("ISPM findings, scan, score and trends are per org", func(t *testing.T) {
		f.seedStaleUser(f.orgA, "ti-stale-a-"+f.orgA[:8])
		f.seedStaleUser(f.orgB, "ti-stale-b-"+f.orgB[:8])

		// A day-old open finding in org A: B's scan must leave it alone, A's
		// scan must clear it (the pre-v138 DELETE had no org predicate).
		f.exec(`INSERT INTO ispm_findings (org_id, check_type, severity, category, title, status, created_at)
			VALUES ($1, 'stale_accounts', 'low', 'accounts', 'old finding', 'open', NOW() - INTERVAL '2 days')`, f.orgA)

		// B scans first.
		w := f.call(f.orgB, f.s.RunPostureChecks, "POST", "/api/v1/ispm/scan", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("B scan: %d %s", w.Code, w.Body.String())
		}
		var scan struct {
			FindingsCreated int `json:"findings_created"`
			ChecksRun       int `json:"checks_run"`
			ChecksSkipped   int `json:"checks_skipped"`
			ChecksFailed    int `json:"checks_failed"`
		}
		decode(t, w, &scan)
		if scan.ChecksFailed != 0 {
			t.Fatalf("B scan reported %d failed checks — a query is wrong for the deployed schema", scan.ChecksFailed)
		}
		if scan.ChecksRun != len(postureCheckDefs) {
			t.Fatalf("B scan ran %d checks, want %d (all default rules enabled)", scan.ChecksRun, len(postureCheckDefs))
		}
		if scan.FindingsCreated < 1 {
			t.Fatalf("B scan created no findings despite a seeded stale user")
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND title = 'old finding'", f.orgA); got != 1 {
			t.Fatalf("B's scan deleted org A's day-old finding (cross-tenant DELETE)")
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND status = 'open' AND created_at > NOW() - INTERVAL '1 minute'", f.orgA); got != 0 {
			t.Fatalf("B's scan created %d findings in org A", got)
		}

		// A scans: its stale finding is cleared, its own findings appear.
		w = f.call(f.orgA, f.s.RunPostureChecks, "POST", "/api/v1/ispm/scan", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("A scan: %d %s", w.Code, w.Body.String())
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND title = 'old finding'", f.orgA); got != 0 {
			t.Fatalf("A's scan did not clear A's own day-old finding")
		}

		// Every finding A lists is A's; B's list never contains A's rows.
		var list struct {
			Data  []PostureFinding `json:"data"`
			Total int              `json:"total"`
		}
		w = f.call(f.orgA, f.s.handleListPostureFindings, "GET", "/api/v1/ispm/findings", nil, nil)
		decode(t, w, &list)
		if list.Total < 1 {
			t.Fatalf("A lists no findings after its scan")
		}
		aFinding := list.Data[0]
		if aFinding.RuleID == nil || *aFinding.RuleID == "" {
			t.Fatalf("finding %s has no rule_id — the scan is not reading ispm_rules", aFinding.ID)
		}
		w = f.call(f.orgB, f.s.handleListPostureFindings, "GET", "/api/v1/ispm/findings", nil, nil)
		var listB struct {
			Data []PostureFinding `json:"data"`
		}
		decode(t, w, &listB)
		for _, fb := range listB.Data {
			if fb.ID == aFinding.ID {
				t.Fatalf("org B lists org A's finding %s", fb.ID)
			}
		}

		// B cannot get, dismiss or remediate A's finding.
		p := map[string]string{"id": aFinding.ID}
		if w = f.call(f.orgB, f.s.handleGetPostureFinding, "GET", "/api/v1/ispm/findings/x", p, nil); w.Code != http.StatusNotFound {
			t.Fatalf("B get A's finding: %d, want 404", w.Code)
		}
		if w = f.call(f.orgB, f.s.handleDismissPostureFinding, "POST", "/api/v1/ispm/findings/x/dismiss", p, map[string]string{"reason": "x"}); w.Code != http.StatusNotFound {
			t.Fatalf("B dismiss A's finding: %d, want 404", w.Code)
		}
		if w = f.call(f.orgB, f.s.handleRemediatePostureFinding, "POST", "/api/v1/ispm/findings/x/remediate", p, nil); w.Code != http.StatusNotFound {
			t.Fatalf("B remediate A's finding: %d, want 404", w.Code)
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE id = $1 AND status = 'open'", aFinding.ID); got != 1 {
			t.Fatalf("A's finding was mutated by org B")
		}
		// A can.
		if w = f.call(f.orgA, f.s.handleGetPostureFinding, "GET", "/api/v1/ispm/findings/x", p, nil); w.Code != http.StatusOK {
			t.Fatalf("A get own finding: %d", w.Code)
		}

		// Scores: one snapshot per org per day; each org's trend is its own.
		if w = f.call(f.orgA, f.s.handleGetPostureScore, "GET", "/api/v1/ispm/score", nil, nil); w.Code != http.StatusOK {
			t.Fatalf("A score: %d %s", w.Code, w.Body.String())
		}
		var scoreA PostureScore
		decode(t, w, &scoreA)
		if scoreA.TotalFindings != list.Total {
			t.Fatalf("A score counts %d open findings, A lists %d — the count is not org-scoped", scoreA.TotalFindings, list.Total)
		}
		if w = f.call(f.orgB, f.s.handleGetPostureScore, "GET", "/api/v1/ispm/score", nil, nil); w.Code != http.StatusOK {
			t.Fatalf("B score: %d %s", w.Code, w.Body.String())
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_scores WHERE snapshot_date = CURRENT_DATE AND org_id IN ($1, $2)", f.orgA, f.orgB); got != 2 {
			t.Fatalf("expected one score snapshot per org today, got %d (one tenant overwrote the other's)", got)
		}
		var trends struct {
			Data []map[string]interface{} `json:"data"`
		}
		w = f.call(f.orgB, f.s.handleGetPostureTrends, "GET", "/api/v1/ispm/trends", nil, nil)
		decode(t, w, &trends)
		if len(trends.Data) != 1 {
			t.Fatalf("B trends returned %d rows, want exactly its own 1", len(trends.Data))
		}
	})

	t.Run("ISPM rules are per org and the scan obeys them", func(t *testing.T) {
		var rulesA, rulesB struct {
			Data []PostureRule `json:"data"`
		}
		w := f.call(f.orgA, f.s.handleListPostureRules, "GET", "/api/v1/ispm/rules", nil, nil)
		decode(t, w, &rulesA)
		w = f.call(f.orgB, f.s.handleListPostureRules, "GET", "/api/v1/ispm/rules", nil, nil)
		decode(t, w, &rulesB)
		if len(rulesA.Data) != len(postureCheckDefs) || len(rulesB.Data) != len(postureCheckDefs) {
			t.Fatalf("rules seeded per org: A=%d B=%d, want %d each", len(rulesA.Data), len(rulesB.Data), len(postureCheckDefs))
		}
		byType := map[string]PostureRule{}
		for _, r := range rulesA.Data {
			if !r.Implemented {
				t.Fatalf("default rule %s reports implemented=false", r.CheckType)
			}
			byType[r.CheckType] = r
		}
		for _, rb := range rulesB.Data {
			if ra, ok := byType[rb.CheckType]; ok && ra.ID == rb.ID {
				t.Fatalf("orgs A and B share rule row %s — rules are not per tenant", rb.ID)
			}
		}

		// B cannot update A's rule.
		stale := byType["stale_accounts"]
		off := false
		w = f.call(f.orgB, f.s.handleUpdatePostureRule, "PUT", "/api/v1/ispm/rules/x", map[string]string{"id": stale.ID}, map[string]interface{}{"enabled": off})
		if w.Code != http.StatusNotFound {
			t.Fatalf("B update A's rule: %d, want 404", w.Code)
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_rules WHERE id = $1 AND enabled = true", stale.ID); got != 1 {
			t.Fatalf("A's rule was changed by org B")
		}

		// A disables stale_accounts and raises mfa_adoption to critical; the
		// next scan skips one check and stamps the new severity.
		w = f.call(f.orgA, f.s.handleUpdatePostureRule, "PUT", "/api/v1/ispm/rules/x", map[string]string{"id": stale.ID}, map[string]interface{}{"enabled": off})
		if w.Code != http.StatusOK {
			t.Fatalf("A disable rule: %d %s", w.Code, w.Body.String())
		}
		mfa := byType["mfa_adoption"]
		w = f.call(f.orgA, f.s.handleUpdatePostureRule, "PUT", "/api/v1/ispm/rules/x", map[string]string{"id": mfa.ID}, map[string]interface{}{"severity": "critical"})
		if w.Code != http.StatusOK {
			t.Fatalf("A set severity: %d %s", w.Code, w.Body.String())
		}
		f.exec("DELETE FROM ispm_findings WHERE org_id = $1", f.orgA)

		w = f.call(f.orgA, f.s.RunPostureChecks, "POST", "/api/v1/ispm/scan", nil, nil)
		var scan struct {
			ChecksRun     int `json:"checks_run"`
			ChecksSkipped int `json:"checks_skipped"`
		}
		decode(t, w, &scan)
		if scan.ChecksSkipped != 1 || scan.ChecksRun != len(postureCheckDefs)-1 {
			t.Fatalf("scan with one disabled rule: run=%d skipped=%d", scan.ChecksRun, scan.ChecksSkipped)
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND check_type = 'stale_accounts'", f.orgA); got != 0 {
			t.Fatalf("disabled stale_accounts rule still produced %d findings — the Rules page is not enforced", got)
		}
		if got := f.count("SELECT COUNT(*) FROM ispm_findings WHERE org_id = $1 AND check_type = 'mfa_adoption' AND severity = 'critical' AND rule_id = $2", f.orgA, mfa.ID); got < 1 {
			t.Fatalf("mfa_adoption findings do not carry the rule's edited severity and rule_id")
		}

		// A rule row for a check with no implementation (the pre-v138 seed
		// shipped six) is reported as such and cannot be switched on.
		var ghostID string
		if err := f.db.Pool.QueryRow(f.bypass(), `
			INSERT INTO ispm_rules (org_id, name, description, category, check_type, severity, enabled)
			VALUES ($1, 'Shadow Admin Detection', 'legacy seed row', 'authorization', 'shadow_admin', 'critical', false) RETURNING id`, f.orgA).Scan(&ghostID); err != nil {
			t.Fatalf("seed legacy rule: %v", err)
		}
		w = f.call(f.orgA, f.s.handleListPostureRules, "GET", "/api/v1/ispm/rules", nil, nil)
		decode(t, w, &rulesA)
		found := false
		for _, r := range rulesA.Data {
			if r.ID == ghostID {
				found = true
				if r.Implemented {
					t.Fatalf("shadow_admin has no check behind it but reports implemented=true")
				}
			}
		}
		if !found {
			t.Fatalf("legacy rule row not listed")
		}
		on := true
		w = f.call(f.orgA, f.s.handleUpdatePostureRule, "PUT", "/api/v1/ispm/rules/x", map[string]string{"id": ghostID}, map[string]interface{}{"enabled": on})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("enabling an unimplemented check: %d, want 400 (a live toggle for a check that never runs)", w.Code)
		}
	})

	t.Run("AI agents and their children are per org", func(t *testing.T) {
		create := func(org, name string) (string, int) {
			w := f.call(org, f.s.handleCreateAIAgent, "POST", "/api/v1/ai-agents", nil, map[string]interface{}{"name": name})
			var resp struct {
				Data   AIAgent `json:"data"`
				APIKey string  `json:"api_key"`
			}
			if w.Code == http.StatusCreated {
				decode(t, w, &resp)
			}
			return resp.Data.ID, w.Code
		}
		// The same agent name in two orgs is two agents (name was globally UNIQUE).
		aID, code := create(f.orgA, "ti-bot")
		if code != http.StatusCreated {
			t.Fatalf("A create: %d", code)
		}
		bID, code := create(f.orgB, "ti-bot")
		if code != http.StatusCreated {
			t.Fatalf("B create with the same name: %d, want 201 — names must be unique per org, not per install", code)
		}
		if got := f.count("SELECT COUNT(*) FROM ai_agent_credentials WHERE agent_id = $1 AND org_id = $2", aID, f.orgA); got != 1 {
			t.Fatalf("A's initial credential is not stamped with A's org (got %d)", got)
		}

		// Lists are disjoint.
		var list struct {
			Data []AIAgent `json:"data"`
		}
		w := f.call(f.orgB, f.s.handleListAIAgents, "GET", "/api/v1/ai-agents", nil, nil)
		decode(t, w, &list)
		for _, a := range list.Data {
			if a.ID == aID {
				t.Fatalf("org B lists org A's agent")
			}
		}
		if len(list.Data) != 1 {
			t.Fatalf("B lists %d agents, want its own 1", len(list.Data))
		}

		// Every by-id handler refuses A's agent for B.
		pa := map[string]string{"id": aID}
		cases := []struct {
			name string
			h    gin.HandlerFunc
			m    string
			body interface{}
		}{
			{"get", f.s.handleGetAIAgent, "GET", nil},
			{"update", f.s.handleUpdateAIAgent, "PUT", map[string]interface{}{"description": "pwned"}},
			{"suspend", f.s.handleSuspendAIAgent, "POST", nil},
			{"rotate", f.s.handleRotateAIAgentCredentials, "POST", nil},
			{"grant", f.s.handleGrantAIAgentPermission, "POST", map[string]interface{}{"resource_type": "users", "actions": []string{"read"}}},
			{"delete", f.s.handleDeleteAIAgent, "DELETE", nil},
		}
		for _, c := range cases {
			w := f.call(f.orgB, c.h, c.m, "/api/v1/ai-agents/x", pa, c.body)
			if w.Code != http.StatusNotFound {
				t.Fatalf("B %s A's agent: %d, want 404", c.name, w.Code)
			}
		}
		if got := f.count("SELECT COUNT(*) FROM ai_agents WHERE id = $1 AND status = 'active' AND COALESCE(description, '') = ''", aID); got != 1 {
			t.Fatalf("A's agent was mutated or deleted by org B")
		}
		if got := f.count("SELECT COUNT(*) FROM ai_agent_credentials WHERE agent_id = $1 AND status = 'active'", aID); got != 1 {
			t.Fatalf("A's credentials were rotated by org B")
		}
		if got := f.count("SELECT COUNT(*) FROM ai_agent_permissions WHERE agent_id = $1", aID); got != 0 {
			t.Fatalf("B attached a permission to A's agent")
		}

		// Child reads by A's agent id from B come back empty, and a
		// permission B revokes must be B's own.
		w = f.call(f.orgA, f.s.handleGrantAIAgentPermission, "POST", "/api/v1/ai-agents/x/permissions", pa, map[string]interface{}{"resource_type": "users", "actions": []string{"read"}})
		if w.Code != http.StatusCreated {
			t.Fatalf("A grant own: %d %s", w.Code, w.Body.String())
		}
		var perm struct {
			Data AIAgentPermission `json:"data"`
		}
		decode(t, w, &perm)
		var perms struct {
			Data []AIAgentPermission `json:"data"`
		}
		w = f.call(f.orgB, f.s.handleListAIAgentPermissions, "GET", "/api/v1/ai-agents/x/permissions", pa, nil)
		decode(t, w, &perms)
		if len(perms.Data) != 0 {
			t.Fatalf("B lists %d of A's agent permissions", len(perms.Data))
		}
		w = f.call(f.orgB, f.s.handleRevokeAIAgentPermission, "DELETE", "/api/v1/ai-agents/x/permissions/y", map[string]string{"id": aID, "permId": perm.Data.ID}, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("B revoke A's permission: %d, want 404", w.Code)
		}

		// Analytics count only the caller's tenant.
		w = f.call(f.orgA, f.s.handleAIAgentAnalytics, "GET", "/api/v1/ai-agents/analytics", nil, nil)
		var analytics map[string]interface{}
		decode(t, w, &analytics)
		if analytics["total_agents"].(float64) != 1 {
			t.Fatalf("A analytics total_agents = %v, want 1 (install-wide count)", analytics["total_agents"])
		}

		// An owner from another tenant is refused.
		bUser := f.seedStaleUser(f.orgB, "ti-owner-b-"+f.orgB[:8])
		w = f.call(f.orgA, f.s.handleCreateAIAgent, "POST", "/api/v1/ai-agents", nil, map[string]interface{}{"name": "ti-bot-2", "owner_id": bUser})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("A create agent owned by B's user: %d, want 400", w.Code)
		}
		_ = bID
	})

	t.Run("AI recommendations are per org", func(t *testing.T) {
		f.seedStaleUser(f.orgA, "ti-rec-a-"+f.orgA[:8])
		f.seedStaleUser(f.orgB, "ti-rec-b-"+f.orgB[:8])
		var gen struct {
			Generated int `json:"generated"`
		}
		w := f.call(f.orgA, f.s.handleGenerateRecommendations, "POST", "/api/v1/recommendations/generate", nil, nil)
		decode(t, w, &gen)
		if gen.Generated < 1 {
			t.Fatalf("A generated nothing")
		}
		w = f.call(f.orgB, f.s.handleGenerateRecommendations, "POST", "/api/v1/recommendations/generate", nil, nil)
		decode(t, w, &gen)
		if gen.Generated < 1 {
			t.Fatalf("B generated nothing — the per-org dedupe treated A's titles as B's")
		}

		var listA, listB struct {
			Data []Recommendation `json:"data"`
		}
		w = f.call(f.orgA, f.s.handleListRecommendations, "GET", "/api/v1/recommendations", nil, nil)
		decode(t, w, &listA)
		w = f.call(f.orgB, f.s.handleListRecommendations, "GET", "/api/v1/recommendations", nil, nil)
		decode(t, w, &listB)
		idsB := map[string]bool{}
		for _, r := range listB.Data {
			idsB[r.ID] = true
		}
		for _, r := range listA.Data {
			if idsB[r.ID] {
				t.Fatalf("recommendation %s is listed by both orgs", r.ID)
			}
		}
		if len(listA.Data) == 0 {
			t.Fatalf("A lists no recommendations")
		}
		target := listA.Data[0]
		p := map[string]string{"id": target.ID}
		for _, c := range []struct {
			name string
			h    gin.HandlerFunc
		}{
			{"get", f.s.handleGetRecommendation},
			{"accept", f.s.handleAcceptRecommendation},
			{"dismiss", f.s.handleDismissRecommendation},
			{"apply", f.s.handleApplyRecommendation},
		} {
			w := f.call(f.orgB, c.h, "POST", "/api/v1/recommendations/x", p, map[string]string{"reason": "x"})
			if w.Code != http.StatusNotFound {
				t.Fatalf("B %s A's recommendation: %d, want 404", c.name, w.Code)
			}
		}
		if got := f.count("SELECT COUNT(*) FROM ai_recommendations WHERE id = $1 AND status = 'pending'", target.ID); got != 1 {
			t.Fatalf("A's recommendation was mutated by org B")
		}
		if got := f.count("SELECT COUNT(*) FROM recommendation_history WHERE recommendation_id = $1", target.ID); got != 0 {
			t.Fatalf("B wrote history onto A's recommendation")
		}

		// A's own accept works and its history row carries A's org.
		w = f.call(f.orgA, f.s.handleAcceptRecommendation, "POST", "/api/v1/recommendations/x/accept", p, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("A accept own: %d %s", w.Code, w.Body.String())
		}
		if got := f.count("SELECT COUNT(*) FROM recommendation_history WHERE recommendation_id = $1 AND org_id = $2", target.ID, f.orgA); got != 1 {
			t.Fatalf("history row missing or not stamped with A's org")
		}

		// Stats are the caller's only.
		w = f.call(f.orgB, f.s.handleRecommendationStats, "GET", "/api/v1/recommendations/stats", nil, nil)
		var stats struct {
			ByStatus map[string]int `json:"by_status"`
		}
		decode(t, w, &stats)
		if stats.ByStatus["accepted"] != 0 {
			t.Fatalf("B's stats count A's accepted recommendation")
		}
	})
}
