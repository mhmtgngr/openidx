package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/openidx/openidx/internal/agentic"
)

// OpenAI is a Provider over an OpenAI-compatible chat completions endpoint:
// Ollama (http://host:11434/v1), vLLM, LM Studio, llama.cpp. It is how an
// organization runs the assistant on its own hardware, with nothing leaving
// the network.
type OpenAI struct {
	base      string
	model     string
	key       string
	toolCalls bool
	hc        *http.Client
}

// OpenAIConfig configures NewOpenAI.
type OpenAIConfig struct {
	BaseURL string // up to and including /v1
	Model   string
	APIKey  string // optional; local servers usually have none
	// NoTools says the model cannot call tools; it then only narrates.
	NoTools bool
	// DenyPrivate also refuses loopback, private (RFC 1918) and unique-local
	// addresses, for a deployment that hosts several organizations and does
	// not want one of them probing its network. By default they are allowed:
	// a model server on the organization's own network is the point.
	DenyPrivate bool
	// Timeout bounds one request (default 60 s).
	Timeout    time.Duration
	HTTPClient *http.Client
}

// NewOpenAI builds the provider. It makes no request.
func NewOpenAI(c OpenAIConfig) (*OpenAI, error) {
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("openai-compatible: base URL must be http(s)://host/v1")
	}
	if c.Model == "" {
		return nil, errors.New("openai-compatible: no model")
	}
	if err := CheckBaseURL(c.BaseURL, c.DenyPrivate); err != nil {
		return nil, err
	}
	hc := c.HTTPClient
	if hc == nil {
		to := c.Timeout
		if to <= 0 {
			to = 60 * time.Second
		}
		hc = &http.Client{
			Timeout: to,
			// A model server that redirects is not one to follow: a redirect
			// is the usual way past an address check.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				// Checked on the address actually dialled, after DNS, so a name
				// that resolves somewhere forbidden is refused too.
				Control: func(_, address string, _ syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return err
					}
					return forbidAddress(net.ParseIP(host), c.DenyPrivate)
				},
			}).DialContext},
		}
	}
	return &OpenAI{base: u.String(), model: c.Model, key: c.APIKey, toolCalls: !c.NoTools, hc: hc}, nil
}

// Capabilities reports whether tools are used.
func (o *OpenAI) Capabilities() agentic.Capabilities {
	return agentic.Capabilities{ToolCalls: o.toolCalls}
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

const maxOpenAIResponse = 1 << 20

// Chat sends one request.
func (o *OpenAI) Chat(ctx context.Context, req agentic.Request) (agentic.Response, error) {
	var msgs []oaMessage
	if req.System != "" {
		s := req.System
		msgs = append(msgs, oaMessage{Role: "system", Content: &s})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, toOpenAIMessages(m)...)
	}
	body := map[string]any{"model": o.model, "messages": msgs, "max_tokens": req.MaxTokens}
	if len(req.Tools) > 0 && o.toolCalls {
		var tools []map[string]any
		for _, t := range req.Tools {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": t.InputSchema}})
		}
		body["tools"] = tools
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return agentic.Response{}, err
	}
	endpoint, err := url.JoinPath(o.base, "chat", "completions")
	if err != nil {
		return agentic.Response{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return agentic.Response{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if o.key != "" {
		hreq.Header.Set("Authorization", "Bearer "+o.key)
	}
	resp, err := o.hc.Do(hreq)
	if err != nil {
		return agentic.Response{}, fmt.Errorf("openai-compatible: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxOpenAIResponse))
	if err != nil {
		return agentic.Response{}, err
	}
	if resp.StatusCode/100 != 2 {
		return agentic.Response{}, fmt.Errorf("openai-compatible: status %d", resp.StatusCode)
	}
	var parsed struct {
		Choices []struct {
			Message      oaMessage `json:"message"`
			FinishReason string    `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Choices) == 0 {
		return agentic.Response{}, errors.New("openai-compatible: unreadable response")
	}
	ch := parsed.Choices[0]
	out := agentic.Response{Usage: agentic.Usage{InputTokens: parsed.Usage.Prompt, OutputTokens: parsed.Usage.Completion}, Stop: agentic.StopEnd}
	if ch.Message.Content != nil && *ch.Message.Content != "" {
		out.Blocks = append(out.Blocks, agentic.Block{Type: agentic.BlockText, Text: *ch.Message.Content})
	}
	for _, tc := range ch.Message.ToolCalls {
		in := json.RawMessage(tc.Function.Arguments)
		if !json.Valid(in) {
			in = json.RawMessage(`{}`)
		}
		out.Blocks = append(out.Blocks, agentic.Block{Type: agentic.BlockToolUse, ToolUseID: tc.ID, Name: tc.Function.Name, Input: in})
	}
	switch {
	case len(ch.Message.ToolCalls) > 0:
		out.Stop = agentic.StopToolUse
	case ch.FinishReason == "length":
		out.Stop = agentic.StopMaxTokens
	}
	return out, nil
}

// toOpenAIMessages maps one runtime message onto chat-completions messages: a
// tool result becomes its own "tool" message.
func toOpenAIMessages(m agentic.Message) []oaMessage {
	var out []oaMessage
	var text strings.Builder
	var calls []oaToolCall
	for _, b := range m.Blocks {
		switch b.Type {
		case agentic.BlockText:
			text.WriteString(b.Text)
		case agentic.BlockToolUse:
			var c oaToolCall
			c.ID, c.Type = b.ToolUseID, "function"
			c.Function.Name = b.Name
			c.Function.Arguments = string(b.Input)
			if c.Function.Arguments == "" {
				c.Function.Arguments = "{}"
			}
			calls = append(calls, c)
		case agentic.BlockToolResult:
			s := b.Text
			out = append(out, oaMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: &s})
		}
	}
	if text.Len() > 0 || len(calls) > 0 {
		role := string(m.Role)
		s := text.String()
		msg := oaMessage{Role: role, ToolCalls: calls}
		if s != "" || len(calls) == 0 {
			msg.Content = &s
		}
		out = append([]oaMessage{msg}, out...)
	}
	return out
}

// forbidAddress refuses the addresses an address-bearing setting must never
// reach even though private networks are fine (a model server on the
// organization's own network is the point, so private and loopback addresses
// are allowed by design; the address is set by an admin of the organization):
// link-local, which holds the cloud metadata service, other metadata ranges,
// the unspecified address and multicast.
func forbidAddress(ip net.IP, denyPrivate bool) error {
	if ip == nil {
		return errors.New("openai-compatible: not an IP address")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // ::ffff:169.254.169.254 is the same address
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("openai-compatible: that address is not allowed")
	}
	if denyPrivate && (ip.IsLoopback() || ip.IsPrivate()) {
		return errors.New("openai-compatible: private addresses are not allowed here")
	}
	for _, n := range metadataNets {
		if n.Contains(ip) {
			return errors.New("openai-compatible: that address is not allowed")
		}
	}
	return nil
}

// metadataNets are the cloud metadata services that are not link-local:
// carrier-grade NAT space (Alibaba's 100.100.100.200) and AWS's IPv6 endpoint.
var metadataNets = func() (out []*net.IPNet) {
	for _, c := range []string{"100.64.0.0/10", "fd00:ec2::/32"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// CheckBaseURL is the save-time check on an endpoint address: http(s), a host,
// and, when the host is a literal IP, one forbidAddress allows. A host name is
// checked again after resolution, when it is dialled.
func CheckBaseURL(raw string, denyPrivate bool) error {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("openai-compatible: base URL must be http(s)://host/v1, with no credentials, query or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return forbidAddress(ip, denyPrivate)
	}
	return nil
}
