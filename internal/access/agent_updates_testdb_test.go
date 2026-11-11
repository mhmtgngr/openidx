package access

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A report's version and update outcome land on the agent's row, are listed
// for the console, filter the list, and an organization's paused ring reaches
// the device in its config.
func TestReportStoresAgentVersion(t *testing.T) {
	c, _, query := newContinuityHarness(t, "version-org")
	e := c.enrolled(c.enrol("version-org-fleet", machine("PC-V", "win2:version", "")))
	hdr := map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}
	w := c.send(http.MethodPost, "/api/v1/access/agent/report", hdr, map[string]any{
		"agent_id": e.AgentID, "results": []any{}, "agent_version": "0.6.4",
		"update_result": map[string]any{"state": "failed", "version": "0.6.5", "error": "msiexec 1603"},
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("report answered %d: %s", w.Code, w.Body.String())
	}
	var version, state string
	query([]any{&version, &state}, `SELECT agent_version, update_state->>'state' FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if version != "0.6.4" || state != "failed" {
		t.Errorf("row version=%q update_state=%q", version, state)
	}
	// A report without a version keeps the stored one.
	c.send(http.MethodPost, "/api/v1/access/agent/report", hdr, map[string]any{"agent_id": e.AgentID, "results": []any{}})
	query([]any{&version}, `SELECT agent_version FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if version != "0.6.4" {
		t.Errorf("a versionless report cleared the version: %q", version)
	}

	var list []agentRecord
	w = c.send(http.MethodGet, "/api/v1/access/agents?version=0.6.4", nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].AgentVersion != "0.6.4" || len(list[0].UpdateState) == 0 {
		t.Fatalf("version filter: %v %s", err, w.Body.String())
	}
	w = c.send(http.MethodGet, "/api/v1/access/agents?version=9.9.9", nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 0 {
		t.Errorf("a version nobody runs listed %d devices", len(list))
	}

	if w := c.send(http.MethodPut, "/api/v1/access/agent/settings", nil, map[string]any{"update_paused": true, "update_pin_version": "0.6.3"}); w.Code != http.StatusOK {
		t.Fatalf("settings answered %d: %s", w.Code, w.Body.String())
	}
	if w := c.send(http.MethodPut, "/api/v1/access/agent/settings", nil, map[string]any{"update_rollout_percent": 140}); w.Code != http.StatusBadRequest {
		t.Errorf("a 140%% rollout answered %d", w.Code)
	}
	w = c.send(http.MethodGet, "/api/v1/access/agent/config", hdr, nil)
	var cfg agentConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.Update == nil {
		t.Fatalf("config has no update block: %s", w.Body.String())
	}
	if !cfg.Update.Paused || cfg.Update.TargetVersion != "0.6.3" || !cfg.Update.AllowDowngrade {
		t.Errorf("update block %+v, want paused and pinned to 0.6.3", *cfg.Update)
	}
	var got agentSettingsView
	w = c.send(http.MethodGet, "/api/v1/access/agent/settings", nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.ClaimMode != "login" || !got.Paused || got.RolloutPercent != 100 {
		t.Errorf("settings read back %s", w.Body.String())
	}
}
