package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/agentic"
)

const schema = `{"type":"object","properties":{"agent_id":{"type":"string"}},"additionalProperties":false}`

func request() agentic.Request {
	return agentic.Request{
		System:    "be brief",
		MaxTokens: 300,
		Messages: []agentic.Message{
			agentic.Text(agentic.RoleUser, "why no connection?"),
			{Role: agentic.RoleAssistant, Blocks: []agentic.Block{
				{Type: agentic.BlockOpaque, Raw: json.RawMessage(`{"type":"thinking","thinking":"","signature":"sig123"}`)},
				{Type: agentic.BlockToolUse, ToolUseID: "tu1", Name: "diagnose_my_device", Input: json.RawMessage(`{}`)},
			}},
			{Role: agentic.RoleUser, Blocks: []agentic.Block{{Type: agentic.BlockToolResult, ToolUseID: "tu1", Text: "<untrusted_data>tunnel down</untrusted_data>"}}},
		},
		Tools: []agentic.ToolSpec{{Name: "diagnose_my_device", Description: "why", InputSchema: json.RawMessage(schema)}},
	}
}

func TestAnthropicRequestAndResponse(t *testing.T) {
	var sent map[string]any
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5",
		 "content":[{"type":"thinking","thinking":"","signature":"sig9"},{"type":"text","text":"Your tunnel is down."},
		            {"type":"tool_use","id":"tu2","name":"list_my_devices","input":{}}],
		 "stop_reason":"tool_use","usage":{"input_tokens":120,"output_tokens":40}}`)
	}))
	defer srv.Close()
	a, err := NewAnthropic(AnthropicConfig{APIKey: "sk-test", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Chat(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if key != "Bearer sk-test" || sent["model"] != "claude-sonnet-5-5" || sent["max_tokens"].(float64) != 300 {
		t.Errorf("sent key=%q body=%v", key, sent)
	}
	if oc, _ := sent["output_config"].(map[string]any); oc["effort"] != "medium" {
		t.Errorf("output_config = %v", sent["output_config"])
	}
	if tc, ok := sent["tool_choice"]; ok {
		t.Errorf("tool_choice must stay unset (forced tool use is refused by current models): %v", tc)
	}
	msgs := sent["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("messages = %v", msgs)
	}
	assistant := msgs[1].(map[string]any)["content"].([]any)
	if assistant[0].(map[string]any)["type"] != "thinking" || assistant[0].(map[string]any)["signature"] != "sig123" {
		t.Errorf("the reasoning block was not replayed unchanged: %v", assistant[0])
	}
	if assistant[1].(map[string]any)["type"] != "tool_use" || msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)["type"] != "tool_result" {
		t.Errorf("tool loop shape = %v", msgs)
	}
	tools := sent["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "diagnose_my_device" {
		t.Errorf("tools = %v", tools)
	}

	if got.Stop != agentic.StopToolUse || got.Usage.InputTokens != 120 || len(got.Blocks) != 3 {
		t.Fatalf("response = %+v", got)
	}
	if got.Blocks[0].Type != agentic.BlockOpaque || got.Blocks[1].Text != "Your tunnel is down." ||
		got.Blocks[2].Type != agentic.BlockToolUse || got.Blocks[2].ToolUseID != "tu2" {
		t.Errorf("blocks = %+v", got.Blocks)
	}
}

func TestAnthropicRefusalAndErrors(t *testing.T) {
	status, body := 200, `{"id":"m","type":"message","role":"assistant","model":"x","content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber"},"usage":{"input_tokens":1,"output_tokens":0}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	a, _ := NewAnthropic(AnthropicConfig{APIKey: "k", BaseURL: srv.URL, HTTPClient: srv.Client()})
	if _, err := a.Chat(context.Background(), agentic.Request{MaxTokens: 10, Messages: []agentic.Message{agentic.Text(agentic.RoleUser, "x")}}); !errors.Is(err, ErrRefused) {
		t.Errorf("a refusal gave %v", err)
	}
	status, body = 400, `{"type":"error","error":{"type":"invalid_request_error","message":"nope"}}`
	if _, err := a.Chat(context.Background(), agentic.Request{MaxTokens: 10, Messages: []agentic.Message{agentic.Text(agentic.RoleUser, "x")}}); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("a 400 gave %v", err)
	}
	if _, err := NewAnthropic(AnthropicConfig{}); err == nil {
		t.Error("a missing key was accepted")
	}
}

func TestOpenAICompatRoundTrip(t *testing.T) {
	var sent map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"checking","tool_calls":[{"id":"c1","type":"function","function":{"name":"list_my_devices","arguments":"{}"}}]},"finish_reason":"tool_calls"}],
		 "usage":{"prompt_tokens":50,"completion_tokens":9}}`)
	}))
	defer srv.Close()
	o, err := NewOpenAI(OpenAIConfig{BaseURL: srv.URL + "/v1/", Model: "llama3.1", APIKey: "local-key"})
	if err != nil {
		t.Fatal(err)
	}
	req := request()
	req.Messages[1].Blocks = req.Messages[1].Blocks[1:] // opaque blocks are another provider's
	got, err := o.Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer local-key" || sent["model"] != "llama3.1" {
		t.Errorf("auth=%q body=%v", auth, sent)
	}
	msgs := sent["messages"].([]any)
	roles := []string{}
	for _, m := range msgs {
		roles = append(roles, m.(map[string]any)["role"].(string))
	}
	if strings.Join(roles, ",") != "system,user,assistant,tool" {
		t.Errorf("roles = %v", roles)
	}
	if msgs[2].(map[string]any)["tool_calls"] == nil || msgs[3].(map[string]any)["tool_call_id"] != "tu1" {
		t.Errorf("tool loop shape = %v", msgs)
	}
	if got.Stop != agentic.StopToolUse || got.Usage.OutputTokens != 9 || len(got.Blocks) != 2 ||
		got.Blocks[1].Name != "list_my_devices" || got.Blocks[0].Text != "checking" {
		t.Errorf("response = %+v", got)
	}

	// A model without tool calling is sent none.
	plain, _ := NewOpenAI(OpenAIConfig{BaseURL: srv.URL + "/v1", Model: "tiny", NoTools: true})
	if plain.Capabilities().ToolCalls {
		t.Error("NoTools still reports tool calls")
	}
	sent = nil
	plain.Chat(context.Background(), request())
	if _, has := sent["tools"]; has {
		t.Error("tools were sent to a model that cannot call them")
	}
}

func TestOpenAIRefusesBadConfigAndServerErrors(t *testing.T) {
	for _, c := range []OpenAIConfig{{BaseURL: "ftp://x/v1", Model: "m"}, {BaseURL: "not a url", Model: "m"}, {BaseURL: "http://h/v1"}} {
		if _, err := NewOpenAI(c); err == nil {
			t.Errorf("%+v was accepted", c)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	o, _ := NewOpenAI(OpenAIConfig{BaseURL: srv.URL, Model: "m"})
	if _, err := o.Chat(context.Background(), request()); err == nil {
		t.Error("a 500 was not an error")
	}
}

func TestNewPicksTheProvider(t *testing.T) {
	if _, err := New(Config{Kind: KindNone}); !errors.Is(err, ErrNone) {
		t.Errorf("none: %v", err)
	}
	if p, err := New(Config{Kind: KindAnthropic, APIKey: "k"}); err != nil || !p.Capabilities().ToolCalls {
		t.Errorf("anthropic: %v", err)
	}
	if _, err := New(Config{Kind: KindOpenAICompat, BaseURL: "http://localhost:11434/v1", Model: "m"}); err != nil {
		t.Errorf("openai: %v", err)
	}
	if ValidKind("gpt") || !ValidKind(KindAnthropic) {
		t.Error("ValidKind")
	}
}
