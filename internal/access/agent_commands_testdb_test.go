package access

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

func (c *continuityHarness) syncCommands(e continuityEnrolment, accept bool) []agentCommandDelivery {
	c.t.Helper()
	hdr := map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}
	if accept {
		hdr["X-Agent-Accept-Commands"] = "1"
	}
	w := c.send(http.MethodGet, "/api/v1/access/agent/config", hdr, nil)
	if w.Code != http.StatusOK {
		c.t.Fatalf("config answered %d: %s", w.Code, w.Body.String())
	}
	var cfg agentConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		c.t.Fatal(err)
	}
	return cfg.Commands
}

func (c *continuityHarness) queue(agentID string, body map[string]any) (int, string) {
	c.t.Helper()
	w := c.send(http.MethodPost, "/api/v1/access/agents/"+agentID+"/commands", nil, body)
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.ID
}

func (c *continuityHarness) result(e continuityEnrolment, id string, body map[string]any) int {
	return c.send(http.MethodPost, "/api/v1/access/agent/commands/"+id+"/result",
		map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, body).Code
}

// A queued command reaches the process that runs commands once, never the
// tray, and its result finishes it.
func TestCommandDeliveredOncePerAgent(t *testing.T) {
	c, _, query := newContinuityHarness(t, "cmd-once-org")
	e := c.enrolled(c.enrol("cmd-once-org-fleet", machine("PC-C", "win2:cmdonce", "")))
	code, id := c.queue(e.AgentID, map[string]any{"kind": "restart"})
	if code != http.StatusCreated || id == "" {
		t.Fatalf("queue answered %d", code)
	}
	if got := c.syncCommands(e, false); len(got) != 0 {
		t.Fatalf("a sync that does not run commands (the tray) took %v", got)
	}
	got := c.syncCommands(e, true)
	if len(got) != 1 || got[0].ID != id || got[0].Kind != "restart" {
		t.Fatalf("first sync got %+v", got)
	}
	if again := c.syncCommands(e, true); len(again) != 0 {
		t.Fatalf("the command was delivered twice: %+v", again)
	}
	if code := c.result(e, id, map[string]any{"status": "done", "result": map[string]any{"message": "restarting"}}); code != http.StatusOK {
		t.Fatalf("result answered %d", code)
	}
	if code := c.result(e, id, map[string]any{"status": "done"}); code != http.StatusNotFound {
		t.Errorf("a second result answered %d, want 404", code)
	}
	var status string
	query([]any{&status}, `SELECT status FROM agent_commands WHERE id = $1::uuid`, id)
	if status != "done" {
		t.Errorf("status %q", status)
	}
	// A queued command can be cancelled; a finished one cannot.
	_, id2 := c.queue(e.AgentID, map[string]any{"kind": "update_now"})
	if w := c.send(http.MethodDelete, "/api/v1/access/agents/"+e.AgentID+"/commands/"+id2, nil, nil); w.Code != http.StatusOK {
		t.Errorf("cancel answered %d", w.Code)
	}
	if w := c.send(http.MethodDelete, "/api/v1/access/agents/"+e.AgentID+"/commands/"+id, nil, nil); w.Code != http.StatusConflict {
		t.Errorf("cancelling a finished command answered %d", w.Code)
	}
	if got := c.syncCommands(e, true); len(got) != 0 {
		t.Errorf("a cancelled command was delivered: %+v", got)
	}
	// Expiry sweeps what nobody picked up.
	_, id3 := c.queue(e.AgentID, map[string]any{"kind": "collect_logs"})
	if _, err := c.h.db.Pool.Exec(c.ctx, `UPDATE agent_commands SET expires_at = NOW() - interval '1 minute' WHERE id = $1::uuid`, id3); err != nil {
		t.Fatal(err)
	}
	c.h.expireAgentCommands(c.ctx)
	query([]any{&status}, `SELECT status FROM agent_commands WHERE id = $1::uuid`, id3)
	if status != "expired" {
		t.Errorf("an overdue command is %q, want expired", status)
	}
	var list []agentCommandRecord
	w := c.send(http.MethodGet, "/api/v1/access/agents/"+e.AgentID+"/commands", nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 3 {
		t.Errorf("list: %v %s", err, w.Body.String())
	}
}

// One device cannot answer another's command.
func TestResultRefusesOtherAgent(t *testing.T) {
	c, _, query := newContinuityHarness(t, "cmd-other-org")
	a := c.enrolled(c.enrol("cmd-other-org-fleet", machine("PC-A", "win2:cmda", "")))
	b := c.enrolled(c.enrol("cmd-other-org-fleet", machine("PC-B", "win2:cmdb", "")))
	_, id := c.queue(a.AgentID, map[string]any{"kind": "restart"})
	c.syncCommands(a, true)
	if code := c.result(b, id, map[string]any{"status": "done"}); code != http.StatusNotFound {
		t.Fatalf("another device's result answered %d, want 404", code)
	}
	var status string
	query([]any{&status}, `SELECT status FROM agent_commands WHERE id = $1::uuid`, id)
	if status != "delivered" {
		t.Errorf("the command became %q", status)
	}
}

// A log bundle over 8 MiB is refused; one under it is stored and downloads
// with its digest.
func TestArtifactOver8MiBRefused(t *testing.T) {
	c, _, _ := newContinuityHarness(t, "cmd-artifact-org")
	e := c.enrolled(c.enrol("cmd-artifact-org-fleet", machine("PC-L", "win2:cmdart", "")))
	_, id := c.queue(e.AgentID, map[string]any{"kind": "collect_logs"})
	c.syncCommands(e, true)
	big := base64.StdEncoding.EncodeToString(make([]byte, maxCommandArtifactBytes+1))
	if code := c.result(e, id, map[string]any{"status": "done", "artifact_b64": big, "artifact_name": "x.tar.gz"}); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized artifact answered %d, want 413", code)
	}
	small := base64.StdEncoding.EncodeToString([]byte("bundle"))
	if code := c.result(e, id, map[string]any{"status": "done", "artifact_b64": small, "artifact_name": "../../evil name.tar.gz"}); code != http.StatusOK {
		t.Fatalf("a small artifact answered %d", code)
	}
	w := c.send(http.MethodGet, "/api/v1/access/agents/"+e.AgentID+"/commands/"+id+"/artifact", nil, nil)
	if w.Code != http.StatusOK || w.Body.String() != "bundle" || w.Header().Get("X-Artifact-SHA256") == "" {
		t.Fatalf("artifact download %d %q", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); strings.Contains(cd, "..") || strings.Contains(cd, "/") || strings.Contains(cd, " name") {
		t.Errorf("unsafe Content-Disposition %q", cd)
	}
}

// uninstall and reenroll pass the fresh-MFA gate; restart does not; and
// uninstall needs a reason.
func TestUninstallNeedsFreshMFA(t *testing.T) {
	c, _, _ := newContinuityHarness(t, "cmd-mfa-org")
	e := c.enrolled(c.enrol("cmd-mfa-org-fleet", machine("PC-M", "win2:cmdmfa", "")))
	stepUp := func(g *gin.Context) {
		if g.GetHeader("X-Fresh") != "1" {
			g.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "step_up_required"})
			return
		}
		g.Next()
	}
	r := gin.New()
	admin := r.Group("/api/v1/access", func(g *gin.Context) {
		g.Request = g.Request.WithContext(orgctx.With(g.Request.Context(), orgctx.Org{ID: c.orgID}))
		g.Set("user_id", c.admin)
		g.Next()
	})
	c.h.RegisterAgentAdminRoutes(admin, stepUp, nil, nil)
	post := func(body map[string]any, fresh bool) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/access/agents/"+e.AgentID+"/commands", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if fresh {
			req.Header.Set("X-Fresh", "1")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	reason := "laptop returned to IT"
	if code := post(map[string]any{"kind": "uninstall", "reason": reason}, false); code != http.StatusForbidden {
		t.Errorf("uninstall without fresh MFA answered %d, want 403", code)
	}
	if code := post(map[string]any{"kind": "reenroll"}, false); code != http.StatusForbidden {
		t.Errorf("reenroll without fresh MFA answered %d, want 403", code)
	}
	if code := post(map[string]any{"kind": "restart"}, false); code != http.StatusCreated {
		t.Errorf("restart answered %d; it needs no fresh MFA", code)
	}
	if code := post(map[string]any{"kind": "uninstall"}, true); code != http.StatusBadRequest {
		t.Errorf("uninstall without a reason answered %d, want 400", code)
	}
	if code := post(map[string]any{"kind": "uninstall", "reason": reason}, true); code != http.StatusCreated {
		t.Errorf("uninstall with fresh MFA and a reason answered %d", code)
	}
	if code := post(map[string]any{"kind": "set_options", "args": map[string]any{"log_level": "loud"}}, false); code != http.StatusBadRequest {
		t.Errorf("a bad log level answered %d", code)
	}
	if code := post(map[string]any{"kind": "set_options", "args": map[string]any{"tray_hidden": true}}, false); code != http.StatusCreated {
		t.Errorf("set_options answered %d", code)
	}
}
