// Package agentic is the runtime the platform's AI assistants run on: a
// provider-neutral conversation contract, a registry of typed tools, and a
// bounded loop that lets a model call them.
//
// The rules decide, the model narrates. A tool is the only way a model
// touches anything, every call goes through Registry.Dispatch, and Dispatch
// checks who is asking (Principal), what the tool may do (Tier against the
// organization's mode), and what the model may see (masking) before and after
// the tool runs. Nothing a model writes can widen any of that: the principal
// is built by the caller from the authenticated request, never from model
// output.
package agentic

import (
	"context"
	"encoding/json"
)

// Role is who spoke.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// BlockType says what a Block holds.
type BlockType string

const (
	BlockText       BlockType = "text"
	BlockToolUse    BlockType = "tool_use"
	BlockToolResult BlockType = "tool_result"
)

// Block is one piece of a message: text, a request to call a tool, or a
// tool's answer.
type Block struct {
	Type BlockType `json:"type"`
	Text string    `json:"text,omitempty"`
	// ToolUseID ties a tool_result to the tool_use it answers.
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

// Message is one turn.
type Message struct {
	Role   Role    `json:"role"`
	Blocks []Block `json:"blocks"`
}

// Text is a one-block text message.
func Text(role Role, s string) Message {
	return Message{Role: role, Blocks: []Block{{Type: BlockText, Text: s}}}
}

// ToolSpec is what a model is told about a tool.
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Request is one call to a provider.
type Request struct {
	System    string
	Messages  []Message
	Tools     []ToolSpec
	MaxTokens int
}

// StopReason is why a provider stopped.
type StopReason string

const (
	StopEnd       StopReason = "end_turn"
	StopToolUse   StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
)

// Usage is what a call cost.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response is a provider's answer.
type Response struct {
	Blocks []Block
	Stop   StopReason
	Usage  Usage
}

// Capabilities says what a provider can do, so the loop degrades instead of
// failing: a model without tool calling still narrates a verdict.
type Capabilities struct {
	ToolCalls bool
}

// Provider is one model behind one endpoint. Implementations live beside this
// package's contract, never inside a caller.
type Provider interface {
	Chat(ctx context.Context, req Request) (Response, error)
	Capabilities() Capabilities
}
