package agentic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Tier is how much a tool can change.
type Tier string

const (
	// TierRead looks and changes nothing.
	TierRead Tier = "read"
	// TierSafeFix changes one device in a reversible way: the fixes the rule
	// engine marks safe.
	TierSafeFix Tier = "safe_fix"
	// TierPropose lays out a change and stores it for a person to decide; it
	// changes nothing itself. It is what a model may do about a step that needs
	// approval: ask for it, in a form an administrator can read, approve or
	// dismiss.
	TierPropose Tier = "propose"
	// TierApproval changes access, policy or the network. A model never runs
	// one itself; it can only ask a person.
	TierApproval Tier = "needs_approval"
)

// Audience is who may have a model call a tool for them.
type Audience string

const (
	// AudienceUser tools act on the asking person's own things.
	AudienceUser Audience = "user"
	// AudienceOperator tools look across the organization; only operators.
	AudienceOperator Audience = "operator"
)

// Principal is who is asking. It is built by the caller from the
// authenticated request and the organization's settings; no part of it ever
// comes from model output.
type Principal struct {
	OrgID    string
	UserID   string
	Operator bool
	// DeviceIDs are the devices (agent ids) the person owns. Operators may
	// name any device of their organization; this list scopes everyone else.
	DeviceIDs []string
}

// OwnsDevice reports whether the principal may name this device.
func (p Principal) OwnsDevice(id string) bool {
	if p.Operator {
		return true
	}
	for _, d := range p.DeviceIDs {
		if d == id {
			return true
		}
	}
	return false
}

// Tool is one thing a model may do.
type Tool struct {
	Name        string
	Description string
	Tier        Tier
	Audience    Audience
	// InputSchema is a JSON Schema object describing the arguments.
	InputSchema json.RawMessage
	// Scope, when set, refuses arguments that name something the principal may
	// not touch. It runs before anything else about the call.
	Scope func(p Principal, input json.RawMessage) error
	// Run does the work, with the principal's authority and no more. The
	// value it returns is marshalled, masked and shown to the model.
	Run func(ctx context.Context, p Principal, input json.RawMessage) (any, error)
}

// ErrOutOfScope is what a Scope returns for an argument the principal may not
// use.
var ErrOutOfScope = errors.New("out of scope")

// ScopeDevice returns a Scope that requires the named string field to be one
// of the principal's devices.
func ScopeDevice(field string) func(Principal, json.RawMessage) error {
	return func(p Principal, input json.RawMessage) error {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(input, &m); err != nil {
			return err
		}
		raw, ok := m[field]
		if !ok {
			return nil // a tool that defaults to "my newest device" names none
		}
		var id string
		if err := json.Unmarshal(raw, &id); err != nil || id == "" {
			return fmt.Errorf("%s must be a device id", field)
		}
		if !p.OwnsDevice(id) {
			return ErrOutOfScope
		}
		return nil
	}
}

// Decode reads a tool's arguments strictly: unknown fields are an error.
func Decode(input json.RawMessage, into any) error {
	if len(bytes.TrimSpace(input)) == 0 {
		input = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// Registry holds the tools. It is built once at start-up.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

// Register adds a tool. A tool with no name, run function, schema or a known
// tier and audience, or a name already taken, is a programming error.
func (r *Registry) Register(t Tool) {
	switch {
	case t.Name == "" || t.Run == nil || len(t.InputSchema) == 0:
		panic("agentic: a tool needs a name, a schema and a Run")
	case t.Tier != TierRead && t.Tier != TierSafeFix && t.Tier != TierPropose && t.Tier != TierApproval:
		panic("agentic: tool " + t.Name + " has no tier")
	case t.Audience != AudienceUser && t.Audience != AudienceOperator:
		panic("agentic: tool " + t.Name + " has no audience")
	}
	if _, dup := r.tools[t.Name]; dup {
		panic("agentic: tool " + t.Name + " is registered twice")
	}
	r.tools[t.Name] = t
}

// allowed says whether the principal may use the tool under the mode. A
// model is only ever offered, and only ever allowed to run, what this says
// yes to.
func allowed(t Tool, p Principal, mode string) (bool, string) {
	if t.Audience == AudienceOperator && !p.Operator {
		return false, "not available to you"
	}
	switch t.Tier {
	case TierRead, TierPropose:
		return mode != "off", "assistant is switched off"
	case TierSafeFix:
		return mode == "tier0" || mode == "tier1", "fixes are not enabled for this organization"
	}
	return false, "this needs a person's approval"
}

// Specs lists what a model may be told about for this principal and mode.
func (r *Registry) Specs(p Principal, mode string) []ToolSpec {
	var out []ToolSpec
	for _, t := range r.tools {
		if ok, _ := allowed(t, p, mode); ok {
			out = append(out, ToolSpec{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Result is what goes back to the model.
type Result struct {
	Content string
	IsError bool
}

// maxToolResult bounds what one tool call shows a model.
const maxToolResult = 8 << 10

// maxToolInput bounds the arguments a model may send.
const maxToolInput = 4 << 10

// Dispatch runs one tool call a model asked for. The order is fixed: the tool
// must exist and be allowed, the arguments must be small and a JSON object, the
// Scope must accept them, and only then does the tool run. What comes back is
// masked, bounded and fenced as data, never as instructions. The audit callback
// hears every outcome.
func (r *Registry) Dispatch(ctx context.Context, p Principal, mode string, level Redaction, call Block, audit Auditor) Result {
	emit := func(kind, reason string) {
		if audit != nil {
			audit(Event{Kind: kind, Tool: call.Name, OrgID: p.OrgID, UserID: p.UserID, Reason: reason})
		}
	}
	deny := func(reason string) Result {
		emit(EventToolDenied, reason)
		return Result{Content: "refused: " + reason, IsError: true}
	}
	t, ok := r.tools[call.Name]
	if !ok {
		return deny("no such tool")
	}
	if ok, why := allowed(t, p, mode); !ok {
		return deny(why)
	}
	input := call.Input
	if len(input) > maxToolInput {
		return deny("arguments too large")
	}
	if len(bytes.TrimSpace(input)) == 0 {
		input = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(input, &obj); err != nil {
		return deny("arguments must be a JSON object")
	}
	if t.Scope != nil {
		if err := t.Scope(p, input); err != nil {
			return deny("that is not yours to ask about")
		}
	}
	out, err := t.Run(ctx, p, input)
	if err != nil {
		emit(EventToolFailed, "")
		// The error text may carry internals; the model gets a fixed line.
		return Result{Content: "the tool could not answer", IsError: true}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		emit(EventToolFailed, "")
		return Result{Content: "the tool could not answer", IsError: true}
	}
	emit(EventToolCalled, "")
	return Result{Content: fence(t.Name, Mask(string(raw), level))}
}

// fence marks a tool's output as data. Anything in it, including text a
// device or a user wrote, is evidence to explain, not an instruction to follow;
// the system prompt says so, and the closing tag cannot be forged from inside.
func fence(name, body string) string {
	if len(body) > maxToolResult {
		body = body[:maxToolResult] + `…[cut]`
	}
	body = strings.ReplaceAll(body, "</untrusted_data>", "</ untrusted_data>")
	return `<untrusted_data tool="` + name + `">` + body + `</untrusted_data>`
}
