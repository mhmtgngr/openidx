package access

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The config tells a fleet-enrolled device that nobody owns it yet, and stops
// once someone does, so the tray offers "Sign in to claim" only then.
func TestConfigSaysUnclaimedUntilOwned(t *testing.T) {
	c, exec, _ := newContinuityHarness(t, "unclaimed-org")
	e := c.enrolled(c.enrol("unclaimed-org-fleet", machine("PC-U", "win2:unclaimed", "")))
	read := func() bool {
		t.Helper()
		w := c.send(http.MethodGet, "/api/v1/access/agent/config",
			map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, nil)
		var cfg agentConfigResponse
		if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg.Unclaimed
	}
	if !read() {
		t.Fatal("a fleet-enrolled device was not told it is unclaimed")
	}
	if err := exec(`UPDATE enrolled_agents SET enrolled_by_user_id = $1::uuid WHERE agent_id = $2`, c.admin, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if read() {
		t.Error("an owned device was told it is unclaimed")
	}
}
