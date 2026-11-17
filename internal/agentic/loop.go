package agentic

import (
	"context"
	"errors"
	"time"
)

// Audit event kinds.
const (
	EventSessionStarted = "agentic.session.started"
	EventToolCalled     = "agentic.tool.called"
	EventToolDenied     = "agentic.tool.denied"
	EventToolFailed     = "agentic.tool.failed"
)

// Event is one thing worth an audit row.
type Event struct {
	Kind   string
	Tool   string
	OrgID  string
	UserID string
	Reason string
}

// Auditor hears every event. It must not block.
type Auditor func(Event)

// Limits bound one conversation turn so a model cannot run up a bill or a
// loop. Zero fields take the defaults.
type Limits struct {
	MaxSteps        int
	MaxToolCalls    int
	MaxOutputTokens int
	MaxTotalTokens  int
	Deadline        time.Duration
}

// DefaultLimits are what a turn gets unless the caller sets its own.
var DefaultLimits = Limits{MaxSteps: 8, MaxToolCalls: 20, MaxOutputTokens: 1024, MaxTotalTokens: 20000, Deadline: 45 * time.Second}

func (l Limits) filled() Limits {
	d := DefaultLimits
	if l.MaxSteps > 0 {
		d.MaxSteps = l.MaxSteps
	}
	if l.MaxToolCalls > 0 {
		d.MaxToolCalls = l.MaxToolCalls
	}
	if l.MaxOutputTokens > 0 {
		d.MaxOutputTokens = l.MaxOutputTokens
	}
	if l.MaxTotalTokens > 0 {
		d.MaxTotalTokens = l.MaxTotalTokens
	}
	if l.Deadline > 0 {
		d.Deadline = l.Deadline
	}
	return d
}

// Session is one assistant talking to one person.
type Session struct {
	Provider  Provider
	Registry  *Registry
	Principal Principal
	// Mode is the organization's autonomy mode in effect (off, observe, tier0,
	// tier1); it decides which tools exist for the model at all.
	Mode      string
	Redaction Redaction
	// System is the instruction text. It is written by the platform and never
	// contains device or user text.
	System string
	Limits Limits
	Audit  Auditor
}

// StopCause says why a turn ended.
type StopCause string

const (
	StoppedEnd       StopCause = "end"
	StoppedSteps     StopCause = "max_steps"
	StoppedToolCalls StopCause = "max_tool_calls"
	StoppedBudget    StopCause = "budget"
	StoppedLength    StopCause = "max_tokens"
)

// Outcome is one finished turn.
type Outcome struct {
	// Text is what to show the person; empty when the turn was cut short.
	Text string
	// Messages are the turns this call added, in order, for the caller to keep.
	Messages  []Message
	Steps     int
	ToolCalls int
	Usage     Usage
	Stopped   StopCause
}

// ErrOff is returned when the mode is off: no model is called.
var ErrOff = errors.New("agentic: the assistant is off for this organization")

// Run takes the person's message and answers it, letting the model call tools
// until it has an answer or a limit is reached. history is what was kept from
// earlier turns; it is not modified.
func (s *Session) Run(ctx context.Context, history []Message, user string) (Outcome, error) {
	if s.Mode == "off" || s.Provider == nil {
		return Outcome{}, ErrOff
	}
	lim := s.Limits.filled()
	ctx, cancel := context.WithTimeout(ctx, lim.Deadline)
	defer cancel()

	if s.Audit != nil {
		s.Audit(Event{Kind: EventSessionStarted, OrgID: s.Principal.OrgID, UserID: s.Principal.UserID})
	}
	var specs []ToolSpec
	if s.Provider.Capabilities().ToolCalls && s.Registry != nil {
		specs = s.Registry.Specs(s.Principal, s.Mode)
	}
	added := []Message{Text(RoleUser, Mask(user, s.Redaction))}
	var out Outcome
	for out.Steps < lim.MaxSteps {
		out.Steps++
		msgs := append(append([]Message{}, history...), added...)
		resp, err := s.Provider.Chat(ctx, Request{System: s.System, Messages: msgs, Tools: specs, MaxTokens: lim.MaxOutputTokens})
		if err != nil {
			out.Messages = added
			return out, err
		}
		out.Usage.InputTokens += resp.Usage.InputTokens
		out.Usage.OutputTokens += resp.Usage.OutputTokens
		added = append(added, Message{Role: RoleAssistant, Blocks: resp.Blocks})

		var uses []Block
		var text string
		for _, b := range resp.Blocks {
			switch b.Type {
			case BlockText:
				text += b.Text
			case BlockToolUse:
				uses = append(uses, b)
			}
		}
		if len(uses) == 0 || resp.Stop != StopToolUse {
			out.Text = text
			out.Stopped = StoppedEnd
			if resp.Stop == StopMaxTokens {
				out.Stopped = StoppedLength
			}
			out.Messages = added
			return out, nil
		}
		if out.Usage.InputTokens+out.Usage.OutputTokens > lim.MaxTotalTokens {
			out.Stopped, out.Messages = StoppedBudget, added
			return out, nil
		}
		results := Message{Role: RoleUser}
		for _, u := range uses {
			out.ToolCalls++
			var r Result
			if out.ToolCalls > lim.MaxToolCalls {
				r = Result{Content: "refused: too many tool calls in one turn", IsError: true}
			} else {
				r = s.Registry.Dispatch(ctx, s.Principal, s.Mode, s.Redaction, u, s.Audit)
			}
			results.Blocks = append(results.Blocks, Block{Type: BlockToolResult, ToolUseID: u.ToolUseID, Text: r.Content, IsError: r.IsError})
		}
		added = append(added, results)
		if out.ToolCalls > lim.MaxToolCalls {
			out.Stopped, out.Messages = StoppedToolCalls, added
			return out, nil
		}
	}
	out.Stopped, out.Messages = StoppedSteps, added
	return out, nil
}
