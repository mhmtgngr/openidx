// Package provider holds the model backends the agentic runtime can talk to:
// Anthropic's Messages API (through the official Go SDK) and any
// OpenAI-compatible chat endpoint (Ollama, vLLM, LM Studio, llama.cpp), which
// is how an organization keeps every prompt on its own network.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	anthropic "github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/openidx/openidx/internal/agentic"
)

// DefaultAnthropicModel is used when an organization names none: the current
// Sonnet, which is fast and cheap enough for a support conversation that only
// narrates what the rules decided.
const DefaultAnthropicModel = "claude-sonnet-5-5"

// ErrRefused is returned when the model declined to answer. The caller falls
// back to the rule engine's own wording; it never retries the same question.
var ErrRefused = errors.New("the model declined to answer")

// Anthropic is a Provider over the Messages API.
type Anthropic struct {
	client anthropic.Client
	model  string
}

// AnthropicConfig configures NewAnthropic.
type AnthropicConfig struct {
	APIKey string
	Model  string
	// BaseURL and HTTPClient exist for tests and for a gateway; both are
	// optional.
	BaseURL    string
	HTTPClient *http.Client
}

// NewAnthropic builds the provider. It makes no request.
func NewAnthropic(c AnthropicConfig) (*Anthropic, error) {
	if c.APIKey == "" {
		return nil, errors.New("anthropic: no API key")
	}
	opts := []option.RequestOption{option.WithAPIKey(c.APIKey)}
	if c.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(c.BaseURL))
	}
	if c.HTTPClient != nil {
		opts = append(opts, option.WithHTTPClient(c.HTTPClient))
	}
	model := c.Model
	if model == "" {
		model = DefaultAnthropicModel
	}
	return &Anthropic{client: anthropic.NewClient(opts...), model: model}, nil
}

// Capabilities: Claude calls tools.
func (*Anthropic) Capabilities() agentic.Capabilities { return agentic.Capabilities{ToolCalls: true} }

// Chat sends one request. Tool choice stays "auto" (forced tool use is not
// accepted by current models), effort is medium (the answer narrates a verdict
// the rules already reached), and the model's reasoning blocks are kept and
// replayed unchanged, as the API requires across a tool loop.
func (a *Anthropic) Chat(ctx context.Context, req agentic.Request) (agentic.Response, error) {
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: int64(req.MaxTokens),
		Messages:  make([]anthropic.MessageParam, 0, len(req.Messages)),
		OutputConfig: anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffortMedium,
		},
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System}}
	}
	for _, m := range req.Messages {
		blocks, err := toAnthropicBlocks(m.Blocks)
		if err != nil {
			return agentic.Response{}, err
		}
		if m.Role == agentic.RoleAssistant {
			params.Messages = append(params.Messages, anthropic.NewAssistantMessage(blocks...))
		} else {
			params.Messages = append(params.Messages, anthropic.NewUserMessage(blocks...))
		}
	}
	for _, t := range req.Tools {
		tp, err := toAnthropicTool(t)
		if err != nil {
			return agentic.Response{}, err
		}
		params.Tools = append(params.Tools, anthropic.ToolUnionParam{OfTool: tp})
	}

	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return agentic.Response{}, fmt.Errorf("anthropic: %w", err)
	}
	out := agentic.Response{Usage: agentic.Usage{InputTokens: int(msg.Usage.InputTokens), OutputTokens: int(msg.Usage.OutputTokens)}}
	switch msg.StopReason {
	case anthropic.StopReasonRefusal:
		return out, ErrRefused
	case anthropic.StopReasonToolUse:
		out.Stop = agentic.StopToolUse
	case anthropic.StopReasonMaxTokens:
		out.Stop = agentic.StopMaxTokens
	default:
		out.Stop = agentic.StopEnd
	}
	for _, b := range msg.Content {
		switch b.Type {
		case "text":
			out.Blocks = append(out.Blocks, agentic.Block{Type: agentic.BlockText, Text: b.Text})
		case "tool_use":
			out.Blocks = append(out.Blocks, agentic.Block{Type: agentic.BlockToolUse, ToolUseID: b.ID, Name: b.Name, Input: b.Input})
		default:
			out.Blocks = append(out.Blocks, agentic.Block{Type: agentic.BlockOpaque, Raw: json.RawMessage(b.RawJSON())})
		}
	}
	return out, nil
}

func toAnthropicBlocks(in []agentic.Block) ([]anthropic.ContentBlockParamUnion, error) {
	out := make([]anthropic.ContentBlockParamUnion, 0, len(in))
	for _, b := range in {
		switch b.Type {
		case agentic.BlockText:
			out = append(out, anthropic.NewTextBlock(b.Text))
		case agentic.BlockToolUse:
			var input any = map[string]any{}
			if len(b.Input) > 0 {
				if err := json.Unmarshal(b.Input, &input); err != nil {
					return nil, fmt.Errorf("anthropic: tool input: %w", err)
				}
			}
			out = append(out, anthropic.NewToolUseBlock(b.ToolUseID, input, b.Name))
		case agentic.BlockToolResult:
			out = append(out, anthropic.NewToolResultBlock(b.ToolUseID, b.Text, b.IsError))
		case agentic.BlockOpaque:
			var u anthropic.ContentBlockParamUnion
			if err := json.Unmarshal(b.Raw, &u); err != nil {
				return nil, fmt.Errorf("anthropic: replaying a block: %w", err)
			}
			out = append(out, u)
		}
	}
	return out, nil
}

func toAnthropicTool(t agentic.ToolSpec) (*anthropic.ToolParam, error) {
	var schema struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
		return nil, fmt.Errorf("anthropic: schema of %s: %w", t.Name, err)
	}
	var extra map[string]any
	_ = json.Unmarshal(t.InputSchema, &extra)
	delete(extra, "type")
	delete(extra, "properties")
	delete(extra, "required")
	tp := &anthropic.ToolParam{
		Name: t.Name,
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: schema.Properties, Required: schema.Required, ExtraFields: extra,
		},
	}
	tp.Description = anthropic.String(t.Description)
	return tp, nil
}
