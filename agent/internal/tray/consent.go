package tray

import (
	"sync"

	"github.com/openidx/openidx/agent/internal/agent"
)

// consentGate turns a blocking yes/no prompt into the deferred decider the
// agent's consent flow expects. The agent asks on every config poll until it
// gets "grant" or "deny"; a prompt that blocks the poll would stall every
// other session. So the first ask for a session opens the prompt in its own
// goroutine and answers "" (deferred); later asks return the recorded answer
// once the person has clicked. Each session is asked once.
type consentGate struct {
	ask func(rs *agent.RemoteSupportBlock) bool // blocks until the person answers; true = allow

	mu      sync.Mutex
	pending map[string]bool   // session id -> prompt open
	answers map[string]string // session id -> "grant" | "deny"
}

func newConsentGate(ask func(rs *agent.RemoteSupportBlock) bool) *consentGate {
	return &consentGate{ask: ask, pending: map[string]bool{}, answers: map[string]string{}}
}

// decide implements agent.ConsentDecider.
func (g *consentGate) decide(rs *agent.RemoteSupportBlock) string {
	if rs == nil || rs.SessionID == "" {
		return "deny"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if d, ok := g.answers[rs.SessionID]; ok {
		return d
	}
	if g.pending[rs.SessionID] {
		return "" // the prompt is still open
	}
	g.pending[rs.SessionID] = true
	go func() {
		d := "deny"
		if g.ask(rs) {
			d = "grant"
		}
		g.mu.Lock()
		g.answers[rs.SessionID] = d
		delete(g.pending, rs.SessionID)
		g.mu.Unlock()
	}()
	return ""
}

// forget drops a session's answer once it is over, so the maps do not grow
// with every session the device ever had.
func (g *consentGate) forget(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.answers, sessionID)
	delete(g.pending, sessionID)
}
