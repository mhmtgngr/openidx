package tray

import (
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
)

// TestTheGateDefersUntilThePersonAnswersThenRemembers: the first ask opens the
// prompt and defers; the answer, once given, is returned on every later ask
// and the prompt is opened once.
func TestTheGateDefersUntilThePersonAnswersThenRemembers(t *testing.T) {
	answer := make(chan bool)
	asked := 0
	g := newConsentGate(func(_ *agent.RemoteSupportBlock) bool {
		asked++
		return <-answer
	})
	rs := &agent.RemoteSupportBlock{SessionID: "s1", ConsentRequired: true, ConsentStatus: "pending"}

	if d := g.decide(rs); d != "" {
		t.Fatalf("first ask must defer while the prompt is open, got %q", d)
	}
	if d := g.decide(rs); d != "" {
		t.Fatalf("a second poll while the prompt is open must still defer, got %q", d)
	}
	answer <- true
	deadline := time.Now().Add(2 * time.Second)
	for g.decide(rs) == "" {
		if time.Now().After(deadline) {
			t.Fatal("the answer never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if d := g.decide(rs); d != "grant" {
		t.Fatalf("after Allow the decision is grant, got %q", d)
	}
	if asked != 1 {
		t.Fatalf("the person was asked %d times, want once", asked)
	}
}

// TestDenyIsDenyAndAnotherSessionIsAskedAgain: a No records deny for that
// session only; a new session id opens a new prompt.
func TestDenyIsDenyAndAnotherSessionIsAskedAgain(t *testing.T) {
	g := newConsentGate(func(rs *agent.RemoteSupportBlock) bool { return rs.SessionID == "yes" })
	wait := func(rs *agent.RemoteSupportBlock) string {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if d := g.decide(rs); d != "" {
				return d
			}
			if time.Now().After(deadline) {
				t.Fatal("no answer")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if d := wait(&agent.RemoteSupportBlock{SessionID: "no"}); d != "deny" {
		t.Fatalf("No must deny, got %q", d)
	}
	if d := wait(&agent.RemoteSupportBlock{SessionID: "yes"}); d != "grant" {
		t.Fatalf("a different session is asked on its own, got %q", d)
	}
	g.forget("yes")
	if d := wait(&agent.RemoteSupportBlock{SessionID: "yes"}); d != "grant" {
		t.Fatalf("after forget the session is asked again, got %q", d)
	}
}

// TestASessionWithoutAnIdIsDenied: nothing to ask about, nothing to grant.
func TestASessionWithoutAnIdIsDenied(t *testing.T) {
	g := newConsentGate(func(_ *agent.RemoteSupportBlock) bool { t.Fatal("must not ask"); return true })
	if d := g.decide(nil); d != "deny" {
		t.Fatalf("nil block: %q", d)
	}
	if d := g.decide(&agent.RemoteSupportBlock{}); d != "deny" {
		t.Fatalf("empty id: %q", d)
	}
}
