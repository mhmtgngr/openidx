package access

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func diagnosticBundle(agentID string, failing ...string) map[string]any {
	checks := []any{map[string]any{"id": "config", "status": "pass", "ms": 1}}
	for _, code := range failing {
		checks = append(checks, map[string]any{"id": "tunnel", "status": "fail", "code": code, "ms": 2})
	}
	return map[string]any{
		"schema": 1, "agent_id": agentID, "agent_version": "0.6.0", "os": "windows",
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"checks":       checks, "repairs": []any{},
		"enrollment": map[string]any{"enrolled": true, "auth_invalid": false, "revoked": false},
		"net":        map[string]any{"proxy_mode": "none", "dns_ok": true},
	}
}

func (c *continuityHarness) uploadDiagnostic(e continuityEnrolment, body map[string]any) (int, map[string]any) {
	c.t.Helper()
	w := c.send(http.MethodPost, "/api/v1/access/agent/diagnostics",
		map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, body)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A device's bundle is stored under the device that sent it, whatever the
// bundle claims, and the answer names the cause.
func TestDiagnosticStoredForTheSendingDevice(t *testing.T) {
	c, _, query := newContinuityHarness(t, "diag-store-org")
	e := c.enrolled(c.enrol("diag-store-org-fleet", machine("PC-D", "win2:diagstore", "")))

	code, out := c.uploadDiagnostic(e, diagnosticBundle("someone-elses-agent", "TUNNEL_DOWN"))
	if code != http.StatusOK {
		t.Fatalf("upload answered %d: %v", code, out)
	}
	verdict, _ := out["verdict"].(map[string]any)
	causes, _ := verdict["causes"].([]any)
	if len(causes) != 1 || causes[0].(map[string]any)["code"] != "TUNNEL_DOWN" || verdict["healthy"] != false {
		t.Errorf("verdict = %v", verdict)
	}

	var agentID, orgID, cause, inBundle string
	query([]any{&agentID, &orgID, &cause, &inBundle},
		`SELECT agent_id, org_id::text, primary_cause, bundle->>'agent_id' FROM agent_diagnostics WHERE id = $1::uuid`, out["id"])
	if agentID != e.AgentID || inBundle != e.AgentID || orgID != c.orgID || cause != "TUNNEL_DOWN" {
		t.Errorf("row = agent %q (bundle says %q) org %q cause %q", agentID, inBundle, orgID, cause)
	}
}

func TestDiagnosticRefusals(t *testing.T) {
	c, _, query := newContinuityHarness(t, "diag-refuse-org")
	e := c.enrolled(c.enrol("diag-refuse-org-fleet", machine("PC-R", "win2:diagrefuse", "")))

	wrongSchema := diagnosticBundle(e.AgentID)
	wrongSchema["schema"] = 2
	smuggled := diagnosticBundle(e.AgentID)
	smuggled["auth_token"] = "x"
	huge := diagnosticBundle(e.AgentID)
	huge["os"] = strings.Repeat("a", 70<<10)

	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"another schema":   {wrongSchema, http.StatusBadRequest},
		"an unknown field": {smuggled, http.StatusBadRequest},
		"over 64 KiB":      {huge, http.StatusRequestEntityTooLarge},
	} {
		if code, _ := c.uploadDiagnostic(e, tc.body); code != tc.want {
			t.Errorf("%s answered %d, want %d", name, code, tc.want)
		}
	}
	bad := continuityEnrolment{AgentID: e.AgentID, AuthToken: "not-the-token"}
	if code, _ := c.uploadDiagnostic(bad, diagnosticBundle(e.AgentID)); code != http.StatusUnauthorized {
		t.Errorf("a wrong credential answered %d, want 401", code)
	}
	var n int
	query([]any{&n}, `SELECT COUNT(*) FROM agent_diagnostics`)
	if n != 0 {
		t.Errorf("%d refused bundles were stored", n)
	}
}

// A device that retries keeps only its recent bundles, and trimming one
// device never touches another's.
func TestDiagnosticsKeepTheRecentFewPerDevice(t *testing.T) {
	c, exec, query := newContinuityHarness(t, "diag-trim-org")
	a := c.enrolled(c.enrol("diag-trim-org-fleet", machine("PC-A", "win2:diagtrima", "")))
	b := c.enrolled(c.enrol("diag-trim-org-fleet", machine("PC-B", "win2:diagtrimb", "")))

	if code, _ := c.uploadDiagnostic(b, diagnosticBundle(b.AgentID)); code != http.StatusOK {
		t.Fatalf("upload answered %d", code)
	}
	for i := 0; i < diagnosticsKeptPerAgent+3; i++ {
		if code, _ := c.uploadDiagnostic(a, diagnosticBundle(a.AgentID)); code != http.StatusOK {
			t.Fatalf("upload %d answered %d", i, code)
		}
	}
	var mine, theirs int
	query([]any{&mine}, `SELECT COUNT(*) FROM agent_diagnostics WHERE agent_id = $1`, a.AgentID)
	query([]any{&theirs}, `SELECT COUNT(*) FROM agent_diagnostics WHERE agent_id = $1`, b.AgentID)
	if mine != diagnosticsKeptPerAgent || theirs != 1 {
		t.Errorf("kept %d of the busy device's and %d of the other's, want %d and 1", mine, theirs, diagnosticsKeptPerAgent)
	}

	if err := exec(`UPDATE agent_diagnostics SET expires_at = NOW() - interval '1 minute' WHERE agent_id = $1`, b.AgentID); err != nil {
		t.Fatal(err)
	}
	c.h.expireAgentDiagnostics(c.ctx)
	query([]any{&mine}, `SELECT COUNT(*) FROM agent_diagnostics WHERE agent_id = $1`, a.AgentID)
	query([]any{&theirs}, `SELECT COUNT(*) FROM agent_diagnostics WHERE agent_id = $1`, b.AgentID)
	if mine != diagnosticsKeptPerAgent || theirs != 0 {
		t.Errorf("after the sweep: %d and %d, want %d and 0", mine, theirs, diagnosticsKeptPerAgent)
	}
}

// A "diagnose" command's answer is filed as the device's diagnostic, and an
// answer with no readable bundle still finishes the command.
func TestDiagnoseCommandResultIsFiledAsADiagnostic(t *testing.T) {
	c, _, query := newContinuityHarness(t, "diag-cmd-org")
	e := c.enrolled(c.enrol("diag-cmd-org-fleet", machine("PC-Q", "win2:diagcmd", "")))

	code, id := c.queue(e.AgentID, map[string]any{"kind": "diagnose"})
	if code != http.StatusCreated || id == "" {
		t.Fatalf("queue answered %d", code)
	}
	if got := c.syncCommands(e, true); len(got) != 1 || got[0].Kind != "diagnose" {
		t.Fatalf("delivered %v", got)
	}
	if code := c.result(e, id, map[string]any{"status": "done",
		"result": map[string]any{"bundle": diagnosticBundle("not-this-agent", "DNS_FAIL")}}); code != http.StatusOK {
		t.Fatalf("result answered %d", code)
	}
	var agentID, source, cause string
	query([]any{&agentID, &source, &cause},
		`SELECT agent_id, source, primary_cause FROM agent_diagnostics WHERE org_id = $1::uuid`, c.orgID)
	if agentID != e.AgentID || source != "command" || cause != "DNS_FAIL" {
		t.Errorf("row = agent %q source %q cause %q", agentID, source, cause)
	}

	_, id = c.queue(e.AgentID, map[string]any{"kind": "diagnose"})
	c.syncCommands(e, true)
	if code := c.result(e, id, map[string]any{"status": "done", "result": map[string]any{"bundle": map[string]any{"schema": 9}}}); code != http.StatusOK {
		t.Fatalf("a result with an unreadable bundle answered %d", code)
	}
	var status string
	var n int
	query([]any{&status}, `SELECT status FROM agent_commands WHERE id = $1::uuid`, id)
	query([]any{&n}, `SELECT COUNT(*) FROM agent_diagnostics`)
	if status != "done" || n != 1 {
		t.Errorf("command is %q and %d diagnostics are stored, want done and 1", status, n)
	}
}
