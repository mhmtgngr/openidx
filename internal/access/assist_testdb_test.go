package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/agentic"
)

func (h *diagnoseHarness) ask(body map[string]any) (int, AssistReply, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/my/assist/messages", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	var out AssistReply
	var generic map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	_ = json.Unmarshal(w.Body.Bytes(), &generic)
	return w.Code, out, generic
}

func (h *diagnoseHarness) count(sql string, args ...any) (n int) {
	h.t.Helper()
	if err := h.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestAssistant(t *testing.T) {
	h, ada, bo := newDiagnoseHarness(t, "assist-org")
	h.agent("ada-pc", ada, "active", "compliant", "1 minute", "degraded")
	h.agent("bo-pc", bo, "active", "compliant", "1 minute", "")

	// No model chosen: the answer is the rule engine's alone.
	code, out, _ := h.ask(map[string]any{"message": "why no connection?"})
	if code != http.StatusOK || out.Assistant || out.Reply != "" || out.Verdict.Verdict.Primary() != "TUNNEL_DOWN" {
		t.Fatalf("no model: %d %+v", code, out)
	}

	// A model of the organization's own, scripted.
	h.exec(`INSERT INTO org_agentic_settings (org_id, mode, provider, model, base_url) VALUES ($1::uuid, 'observe', 'openai_compat', 'm', 'http://x/v1')`, h.orgID)
	prov := &agentic.Scripted{ToolCalls: true, Answers: []agentic.Response{
		agentic.CallTool("t1", "diagnose_my_device", `{}`),
		agentic.Say("Your tunnel is down. Restart the OpenIDX agent."),
		agentic.Say("Open the tray icon and choose restart."),
	}}
	h.svc.agentic.providerOverride = prov

	code, out, _ = h.ask(map[string]any{"message": "why can't I connect? mail me at ada@example.com", "lang": "en"})
	if code != http.StatusOK || !out.Assistant || out.Reply != "Your tunnel is down. Restart the OpenIDX agent." || out.SessionID == "" {
		t.Fatalf("answer: %d %+v", code, out)
	}
	if out.Verdict.Verdict.Primary() != "TUNNEL_DOWN" {
		t.Errorf("the verdict must come from the rules: %+v", out.Verdict)
	}
	first := prov.Requests[0]
	if !strings.Contains(first.System, "TUNNEL_DOWN") || strings.Contains(first.System, "ada@example.com") {
		t.Errorf("system prompt = %q", first.System)
	}
	if strings.Contains(first.Messages[0].Blocks[0].Text, "ada@example.com") {
		t.Error("the person's e-mail address reached the model")
	}
	if len(first.Tools) != 2 {
		t.Errorf("a user observing was offered %d tools, want the two read tools", len(first.Tools))
	}
	if n := h.count(`SELECT COUNT(*) FROM agentic_messages WHERE session_id = $1::uuid AND jsonb_array_length(blocks) > 0`, out.SessionID); n != 4 {
		t.Errorf("stored %d turns, want 4 (question, tool call, tool result, answer)", n)
	}

	// The conversation continues from what the server kept.
	_, again, _ := h.ask(map[string]any{"session_id": out.SessionID, "message": "how?"})
	if again.Reply != "Open the tray icon and choose restart." || len(prov.Requests[2].Messages) != 5 {
		t.Errorf("continue: %+v, history sent %d", again, len(prov.Requests[2].Messages))
	}

	// Someone else's conversation, and someone else's device, are not found.
	caller := bo
	h.as = &caller
	if code, _, _ := h.ask(map[string]any{"session_id": out.SessionID, "message": "hi"}); code != http.StatusNotFound {
		t.Errorf("another person's conversation answered %d", code)
	}
	if code, _, _ := h.ask(map[string]any{"agent_id": "ada-pc", "message": "hi"}); code != http.StatusNotFound {
		t.Errorf("another person's device answered %d", code)
	}
	back := ada
	h.as = &back

	// A model that fails leaves the verdict standing.
	h.svc.agentic.providerOverride = &agentic.Scripted{Err: errors.New("provider down")}
	if code, out, _ := h.ask(map[string]any{"message": "again"}); code != http.StatusOK || out.Assistant || !out.Degraded || out.Verdict.Verdict.Primary() != "TUNNEL_DOWN" {
		t.Errorf("degraded: %d %+v", code, out)
	}

	// The kill switch and an off mode stop the model, not the verdict.
	h.svc.agentic.providerOverride = &agentic.Scripted{Answers: []agentic.Response{agentic.Say("hi")}}
	h.exec(`UPDATE org_agentic_settings SET kill_switch = TRUE WHERE org_id = $1::uuid`, h.orgID)
	if _, out, _ := h.ask(map[string]any{"message": "again"}); out.Assistant || out.Verdict.Verdict.Primary() != "TUNNEL_DOWN" {
		t.Errorf("kill switch: %+v", out)
	}
	h.exec(`UPDATE org_agentic_settings SET kill_switch = FALSE WHERE org_id = $1::uuid`, h.orgID)

	// Bad input, and the per-person rate limit.
	for _, msg := range []string{"", "   ", strings.Repeat("x", maxAssistMessageRunes+1)} {
		if code, _, _ := h.ask(map[string]any{"message": msg}); code != http.StatusBadRequest {
			t.Errorf("message of %d chars answered %d", len(msg), code)
		}
	}
	h.exec(`INSERT INTO agentic_sessions (org_id, user_id) VALUES ($1::uuid, $2::uuid)`, h.orgID, ada)
	for i := 0; i < assistRatePerWindow; i++ {
		h.exec(`INSERT INTO agentic_messages (org_id, session_id, seq, role, blocks)
		        SELECT $1::uuid, id, 1000 + $3::int, 'user', '[]'::jsonb FROM agentic_sessions WHERE user_id = $2::uuid ORDER BY created_at DESC LIMIT 1`,
			h.orgID, ada, i)
	}
	if code, _, _ := h.ask(map[string]any{"message": "one more"}); code != http.StatusTooManyRequests {
		t.Errorf("past the rate limit answered %d", code)
	}
	// Failed attempts count too: a person whose model keeps failing cannot
	// ask without limit.
	h.exec(`DELETE FROM agentic_messages WHERE org_id = $1::uuid`, h.orgID)
	h.svc.agentic.providerOverride = &agentic.Scripted{Err: errors.New("provider down")}
	for i := 0; i < assistRatePerWindow; i++ {
		if code, _, _ := h.ask(map[string]any{"message": "again"}); code != http.StatusOK {
			t.Fatalf("attempt %d answered %d", i, code)
		}
	}
	if code, _, _ := h.ask(map[string]any{"message": "again"}); code != http.StatusTooManyRequests {
		t.Errorf("after %d failed attempts the next answered %d, want 429", assistRatePerWindow, code)
	}
}
