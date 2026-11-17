package agentic

import (
	"context"
	"errors"
	"sync"
)

// Scripted is a Provider that plays back fixed answers, in order, and records
// what it was asked. It is for tests of everything that sits on the runtime;
// it makes no network call and has no model behind it.
type Scripted struct {
	mu        sync.Mutex
	Answers   []Response
	Err       error
	ToolCalls bool
	// Requests is every request received, oldest first.
	Requests []Request
}

// Chat returns the next scripted answer, or an error when they run out.
func (s *Scripted) Chat(_ context.Context, req Request) (Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests = append(s.Requests, req)
	if s.Err != nil {
		return Response{}, s.Err
	}
	if len(s.Requests) > len(s.Answers) {
		return Response{}, errors.New("scripted provider: out of answers")
	}
	return s.Answers[len(s.Requests)-1], nil
}

// Capabilities reports ToolCalls as set.
func (s *Scripted) Capabilities() Capabilities { return Capabilities{ToolCalls: s.ToolCalls} }

// Say is a scripted plain answer.
func Say(text string) Response {
	return Response{Blocks: []Block{{Type: BlockText, Text: text}}, Stop: StopEnd, Usage: Usage{InputTokens: 10, OutputTokens: 5}}
}

// CallTool is a scripted request to call one tool.
func CallTool(id, name, input string) Response {
	return Response{
		Blocks: []Block{{Type: BlockToolUse, ToolUseID: id, Name: name, Input: []byte(input)}},
		Stop:   StopToolUse, Usage: Usage{InputTokens: 10, OutputTokens: 5},
	}
}
