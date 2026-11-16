package access

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

func (c *continuityHarness) settingsRouter() *gin.Engine {
	s := &Service{db: c.h.db, logger: zap.NewNop(), config: c.h.conf}
	r := gin.New()
	api := r.Group("/api/v1/access", func(g *gin.Context) {
		g.Request = g.Request.WithContext(orgctx.With(g.Request.Context(), orgctx.Org{ID: c.orgID}))
		g.Set("user_id", c.admin)
		g.Next()
	})
	api.GET("/agentic/settings", s.handleGetAgenticSettings)
	api.PUT("/agentic/settings", s.handlePutAgenticSettings)
	api.GET("/agentic/actions", s.handleListAgenticActions)
	return r
}

func (c *continuityHarness) putSettings(body map[string]any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/access/agentic/settings", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c.settingsRouter().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// Until an organization chooses, the platform watches and does nothing.
func TestAutoFixesObserveByDefault(t *testing.T) {
	c, _, query := newContinuityHarness(t, "agentic-observe-org")
	e := c.enrolled(c.enrol("agentic-observe-org-fleet", machine("PC-O", "win2:agenticobs", "")))
	if code, _ := c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN")); code != http.StatusOK {
		t.Fatalf("upload answered %d", code)
	}
	var observed, commands int
	query([]any{&observed}, `SELECT COUNT(*) FROM agentic_actions WHERE agent_id = $1 AND outcome = 'observed' AND mode = 'observe'`, e.AgentID)
	query([]any{&commands}, `SELECT COUNT(*) FROM agent_commands WHERE agent_id = $1 AND reason LIKE 'automatic fix%'`, e.AgentID)
	if observed != 2 || commands != 0 {
		t.Errorf("observed %d (want restart_tunnel and collect_logs = 2), queued %d (want 0)", observed, commands)
	}
	// The same report again does not repeat the same line.
	c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN"))
	query([]any{&observed}, `SELECT COUNT(*) FROM agentic_actions WHERE agent_id = $1`, e.AgentID)
	if observed != 2 {
		t.Errorf("a repeat report wrote %d ledger rows, want still 2", observed)
	}
}

func TestAutoFixesApplyHoldAndStop(t *testing.T) {
	c, exec, query := newContinuityHarness(t, "agentic-apply-org")
	e := c.enrolled(c.enrol("agentic-apply-org-fleet", machine("PC-A", "win2:agenticapply", "")))

	if code, out := c.putSettings(map[string]any{"mode": "tier0"}); code != http.StatusOK || out["effective_mode"] != "tier0" {
		t.Fatalf("set tier0: %d %v", code, out)
	}
	count := func(where string, args ...any) (n int) {
		t.Helper()
		query([]any{&n}, `SELECT COUNT(*) FROM agentic_actions WHERE agent_id = $1 AND `+where, append([]any{e.AgentID}, args...)...)
		return n
	}
	queued := func() (n int) {
		t.Helper()
		query([]any{&n}, `SELECT COUNT(*) FROM agent_commands WHERE agent_id = $1 AND reason LIKE 'automatic fix%' AND status = 'queued'`, e.AgentID)
		return n
	}

	c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN"))
	if count("outcome = 'applied'") != 2 || queued() != 2 {
		t.Fatalf("tier0 applied %d and queued %d, want 2 and 2", count("outcome = 'applied'"), queued())
	}
	var kinds string
	query([]any{&kinds}, `SELECT string_agg(kind, ',' ORDER BY kind) FROM agent_commands WHERE agent_id = $1`, e.AgentID)
	if kinds != "collect_logs,restart" {
		t.Errorf("queued kinds = %q", kinds)
	}

	// A report an hour or less later does not repeat what was just done.
	c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN"))
	if queued() != 2 || count("outcome = 'applied'") != 2 {
		t.Errorf("a repeat report: queued %d, applied rows %d, want 2 and 2", queued(), count("outcome = 'applied'"))
	}

	// Later, still failing: tried a second time. Later again: the day's
	// allowance is spent and a person takes over.
	for round := 0; round < 2; round++ {
		exec(`UPDATE agent_commands SET status = 'done' WHERE agent_id = $1`, e.AgentID)
		exec(`UPDATE agentic_actions SET created_at = created_at - interval '2 hours' WHERE agent_id = $1`, e.AgentID)
		c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN"))
	}
	if count("outcome = 'applied'") != 4 || count("reason = 'anti_flap'") != 2 || queued() != 0 {
		t.Errorf("after the allowance: applied %d, anti_flap %d, queued %d, want 4, 2 and 0",
			count("outcome = 'applied'"), count("reason = 'anti_flap'"), queued())
	}

	// The kill switch stops a fresh device at once, even in tier0.
	o := c.enrolled(c.enrol("agentic-apply-org-fleet", machine("PC-K", "win2:agentickill", "")))
	if code, out := c.putSettings(map[string]any{"kill_switch": true}); code != http.StatusOK || out["kill_switch"] != true {
		t.Fatalf("kill switch: %d %v", code, out)
	}
	c.uploadDiagnostic(o, diagnosticBundle(o.AgentID, "TUNNEL_DOWN"))
	var killed, others int
	query([]any{&killed}, `SELECT COUNT(*) FROM agentic_actions WHERE agent_id = $1 AND reason = 'kill_switch'`, o.AgentID)
	query([]any{&others}, `SELECT COUNT(*) FROM agent_commands WHERE agent_id = $1 AND reason LIKE 'automatic fix%'`, o.AgentID)
	if killed != 2 || others != 0 {
		t.Errorf("kill switch: %d suppressed, %d queued, want 2 and 0", killed, others)
	}
}

func TestAgenticModeIsCappedByTheDeploymentAndValidated(t *testing.T) {
	c, _, query := newContinuityHarness(t, "agentic-cap-org")
	c.h.conf = &config.Config{AgenticMode: "observe"}
	e := c.enrolled(c.enrol("agentic-cap-org-fleet", machine("PC-C", "win2:agenticcap", "")))

	if code, out := c.putSettings(map[string]any{"mode": "tier1"}); code != http.StatusOK ||
		out["mode"] != "tier1" || out["effective_mode"] != "observe" {
		t.Fatalf("tier1 under an observe cap: %d %v", code, out)
	}
	c.uploadDiagnostic(e, diagnosticBundle(e.AgentID, "TUNNEL_DOWN"))
	var applied int
	query([]any{&applied}, `SELECT COUNT(*) FROM agentic_actions WHERE agent_id = $1 AND outcome = 'applied'`, e.AgentID)
	if applied != 0 {
		t.Errorf("%d fixes were applied under an observe cap", applied)
	}
	for _, bad := range []map[string]any{{"mode": "root"}} {
		if code, _ := c.putSettings(bad); code != http.StatusBadRequest {
			t.Errorf("%v answered %d, want 400", bad, code)
		}
	}
}

// One organization's settings and ledger are not another's.
func TestAgenticSettingsAreOrgScoped(t *testing.T) {
	c, exec, query := newContinuityHarness(t, "agentic-scope-org")
	if code, _ := c.putSettings(map[string]any{"mode": "tier0"}); code != http.StatusOK {
		t.Fatal("could not save the setting")
	}
	var other string
	query([]any{&other}, `INSERT INTO organizations (name, slug) VALUES ('agentic-other', 'agentic-other') RETURNING id::text`)
	if err := exec(`INSERT INTO org_agentic_settings (org_id, mode) VALUES ($1::uuid, 'off')`, other); err != nil {
		t.Fatal(err)
	}
	set, err := loadAgenticSettings(orgctx.With(c.ctx, orgctx.Org{ID: c.orgID}), c.h.db, c.orgID, "")
	if err != nil || set.Mode != modeTier0 {
		t.Errorf("own settings = %+v, %v", set, err)
	}
}

func TestAssistantProviderSettings(t *testing.T) {
	c, _, query := newContinuityHarness(t, "agentic-provider-org")
	put := c.putSettings

	// A cloud model needs the organization's explicit say-so, a key and masking.
	for name, body := range map[string]map[string]any{
		"no consent":                       {"provider": "anthropic", "api_key": "sk-ant-secret-1"},
		"masking off":                      {"provider": "anthropic", "api_key": "sk-ant-secret-1", "cloud_consent": true, "redaction": "off"},
		"no key anywhere":                  {"provider": "anthropic", "cloud_consent": true},
		"a local model without an address": {"provider": "openai_compat", "model": "llama3.1"},
		"an unknown provider":              {"provider": "gpt"},
		"a file address":                   {"provider": "openai_compat", "model": "m", "base_url": "file:///etc/passwd"},
	} {
		if code, out := put(body); code != http.StatusBadRequest {
			t.Errorf("%s answered %d: %v", name, code, out)
		}
	}
	var n int
	query([]any{&n}, `SELECT COUNT(*) FROM org_agentic_settings`)
	if n != 0 {
		t.Errorf("%d refused changes were stored", n)
	}

	code, out := put(map[string]any{"provider": "anthropic", "api_key": "sk-ant-secret-1", "cloud_consent": true})
	if code != http.StatusOK || out["provider"] != "anthropic" || out["has_api_key"] != true || out["cloud_consent_at"] == nil {
		t.Fatalf("anthropic: %d %v", code, out)
	}
	if raw, _ := json.Marshal(out); bytes.Contains(raw, []byte("sk-ant-secret-1")) {
		t.Error("the API key was returned")
	}
	var stored, by string
	query([]any{&stored}, `SELECT api_key_enc FROM org_agentic_settings WHERE org_id = $1::uuid`, c.orgID)
	query([]any{&by}, `SELECT COALESCE(cloud_consent_by::text, '') FROM org_agentic_settings WHERE org_id = $1::uuid`, c.orgID)
	if stored == "" || by != c.admin {
		t.Errorf("stored key %q, consent by %q (want the admin %q)", stored, by, c.admin)
	}

	// The key opens into a working provider; changing only the model keeps
	// the consent and the key.
	set, err := loadAgenticSettings(orgctx.With(c.ctx, orgctx.Org{ID: c.orgID}), c.h.db, c.orgID, "")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{db: c.h.db, logger: zap.NewNop()}
	if p, err := svc.agenticProvider(set); err != nil || !p.Capabilities().ToolCalls {
		t.Errorf("provider from stored settings: %v", err)
	}
	if code, out := put(map[string]any{"model": "claude-opus-5-5"}); code != http.StatusOK || out["has_api_key"] != true || out["cloud_consent_at"] == nil {
		t.Errorf("model change: %d %v", code, out)
	}

	// Moving to a model of their own drops the cloud consent; coming back
	// asks again.
	if code, out := put(map[string]any{"provider": "openai_compat", "model": "llama3.1", "base_url": "http://ollama.internal:11434/v1", "redaction": "off"}); code != http.StatusOK || out["cloud_consent_at"] != nil {
		t.Errorf("local model: %d %v", code, out)
	}
	if code, _ := put(map[string]any{"provider": "anthropic"}); code != http.StatusBadRequest {
		t.Errorf("returning to the cloud without consent answered %d", code)
	}
}
