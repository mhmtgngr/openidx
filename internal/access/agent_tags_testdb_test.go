package access

import (
	"encoding/json"
	"net/http"
	"testing"
)

func (c *continuityHarness) checkTypes(e continuityEnrolment) map[string]bool {
	c.t.Helper()
	w := c.send(http.MethodGet, "/api/v1/access/agent/config",
		map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, nil)
	var cfg agentConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		c.t.Fatalf("config: %v %s", err, w.Body.String())
	}
	out := map[string]bool{}
	for _, ch := range cfg.Checks {
		out[ch.CheckType] = true
	}
	return out
}

// A check with tags reaches only devices carrying one; an untagged check
// reaches every device; retagging a device moves it in and out.
func TestChecksTargetedByTagReachOnlyTaggedAgents(t *testing.T) {
	c, exec, _ := newContinuityHarness(t, "tag-check-org")
	finance := c.enrolled(c.enrol("tag-check-org-fleet", machine("PC-FIN", "win2:tagfin", "")))
	other := c.enrolled(c.enrol("tag-check-org-fleet", machine("PC-OPS", "win2:tagops", "")))
	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+finance.AgentID+"/tags", nil,
		map[string]any{"tags": []string{"Finance", " kiosk "}}); w.Code != http.StatusOK {
		t.Fatalf("set tags answered %d: %s", w.Code, w.Body.String())
	}
	for _, q := range []struct{ name, typ, tags string }{
		{"everyone", "firewall", ""},
		{"finance only", "disk_encryption", `["finance"]`},
		{"lab only", "antivirus", `["lab"]`},
	} {
		var tags any
		if q.tags != "" {
			tags = q.tags
		}
		if err := exec(`INSERT INTO posture_checks (name, check_type, parameters, enabled, severity, org_id, tags)
			VALUES ($1, $2, '{}', true, 'high', $3, $4::jsonb)`, q.name, q.typ, c.orgID, tags); err != nil {
			t.Fatalf("seed %s: %v", q.name, err)
		}
	}
	got := c.checkTypes(finance)
	if !got["firewall"] || !got["disk_encryption"] || got["antivirus"] {
		t.Errorf("finance device got %v, want firewall and disk_encryption", got)
	}
	got = c.checkTypes(other)
	if !got["firewall"] || got["disk_encryption"] || got["antivirus"] {
		t.Errorf("untagged device got %v, want firewall only", got)
	}

	var list []agentRecord
	w := c.send(http.MethodGet, "/api/v1/access/agents?tag=finance", nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].AgentID != finance.AgentID {
		t.Fatalf("?tag=finance listed %s", w.Body.String())
	}
	if len(list[0].Tags) != 2 || list[0].Tags[0] != "finance" || list[0].Tags[1] != "kiosk" {
		t.Errorf("tags normalized to %v", list[0].Tags)
	}

	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+finance.AgentID+"/tags", nil, map[string]any{"tags": []string{}}); w.Code != http.StatusOK {
		t.Fatalf("clear tags answered %d", w.Code)
	}
	if got := c.checkTypes(finance); got["disk_encryption"] {
		t.Errorf("a device whose tag was removed still gets the tagged check: %v", got)
	}
	if w := c.send(http.MethodPut, "/api/v1/access/agents/agent-nope/tags", nil, map[string]any{"tags": []string{"x"}}); w.Code != http.StatusNotFound {
		t.Errorf("tagging an unknown device answered %d", w.Code)
	}
}

// A fleet token's default tags land on every device it enrols, merged with
// what an administrator added.
func TestTokenDefaultTagsLandOnDevice(t *testing.T) {
	c, exec, query := newContinuityHarness(t, "tag-token-org")
	var tokenID string
	query([]any{&tokenID}, `SELECT id::text FROM agent_enrollment_tokens WHERE org_id = $1`, c.orgID)
	if err := exec(`UPDATE agent_enrollment_tokens SET default_tags = '{pilot,finance}' WHERE id = $1::uuid`, tokenID); err != nil {
		t.Fatal(err)
	}
	e := c.enrolled(c.enrol("tag-token-org-fleet", machine("PC-T", "win2:tagtoken", "")))
	var tags []string
	query([]any{&tags}, `SELECT tags FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if len(tags) != 2 {
		t.Fatalf("device tags %v, want the token's two", tags)
	}
	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+e.AgentID+"/tags", nil,
		map[string]any{"tags": []string{"pilot", "finance", "vip"}}); w.Code != http.StatusOK {
		t.Fatalf("set tags answered %d", w.Code)
	}
	c.enrolled(c.enrol("tag-token-org-fleet", machine("PC-T", "win2:tagtoken", "")))
	query([]any{&tags}, `SELECT tags FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if len(tags) != 3 {
		t.Errorf("re-enrolment dropped an administrator's tag: %v", tags)
	}
}
