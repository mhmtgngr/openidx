package agent

import (
	"net"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/remotesupport"
	"github.com/openidx/openidx/agent/internal/transport"
)

// consentMock records SendConsent calls so the test can assert the device's
// half of the attended-support handshake.
type consentMock struct {
	sent     []string // "sessionID:decision"
	failNext bool
}

func (m *consentMock) Enroll(string) (*transport.EnrollResponse, error) { return nil, nil }
func (m *consentMock) ReportResults([]byte) error                       { return nil }
func (m *consentMock) GetConfig() ([]byte, error)                       { return nil, nil }
func (m *consentMock) DialServiceConn(string) (net.Conn, error)         { return nil, errConsent }
func (m *consentMock) SendConsent(sessionID, decision string) error {
	if m.failNext {
		m.failNext = false
		return errConsent
	}
	m.sent = append(m.sent, sessionID+":"+decision)
	return nil
}

var errConsent = &consentErr{}

type consentErr struct{}

func (consentErr) Error() string { return "boom" }

func newTestAgent(m *consentMock) *Agent {
	return &Agent{logger: zap.NewNop(), client: m}
}

func TestProcessConsent_NoBlockIsNoop(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.processRemoteSupportConsent(nil)
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s1", ConsentRequired: false, ConsentStatus: "pending"})
	if len(m.sent) != 0 {
		t.Fatalf("no consent should be sent, got %v", m.sent)
	}
}

func TestProcessConsent_DefaultGrants(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s1", ConsentRequired: true, ConsentStatus: "pending"})
	if len(m.sent) != 1 || m.sent[0] != "s1:grant" {
		t.Fatalf("default policy must grant, got %v", m.sent)
	}
}

func TestProcessConsent_IdempotentPerSession(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	blk := &RemoteSupportBlock{SessionID: "s1", ConsentRequired: true, ConsentStatus: "pending"}
	a.processRemoteSupportConsent(blk)
	a.processRemoteSupportConsent(blk) // second poll, same session
	if len(m.sent) != 1 {
		t.Fatalf("consent must be sent at most once per session, got %v", m.sent)
	}
}

func TestProcessConsent_AlreadyGrantedIsNoop(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s1", ConsentRequired: true, ConsentStatus: "granted"})
	if len(m.sent) != 0 {
		t.Fatalf("granted session needs no action, got %v", m.sent)
	}
}

func TestProcessConsent_CustomDeciderDeny(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.ConsentDecider = func(_ *RemoteSupportBlock) string { return "deny" }
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s2", ConsentRequired: true, ConsentStatus: "pending"})
	if len(m.sent) != 1 || m.sent[0] != "s2:deny" {
		t.Fatalf("custom decider must be honored, got %v", m.sent)
	}
}

func TestProcessConsent_DeferRetries(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	deferred := true
	a.ConsentDecider = func(_ *RemoteSupportBlock) string {
		if deferred {
			deferred = false
			return "" // prompt still open
		}
		return "grant"
	}
	blk := &RemoteSupportBlock{SessionID: "s3", ConsentRequired: true, ConsentStatus: "pending"}
	a.processRemoteSupportConsent(blk) // deferred: nothing sent, not marked handled
	if len(m.sent) != 0 {
		t.Fatalf("deferred decision must not send, got %v", m.sent)
	}
	a.processRemoteSupportConsent(blk) // now grants
	if len(m.sent) != 1 || m.sent[0] != "s3:grant" {
		t.Fatalf("retry must grant after defer, got %v", m.sent)
	}
}

// TestControlTrackingSinkMirrorsControlState verifies the agent's banner
// "controlled" flag follows the admin's control_state, and that Apply is
// gated by nothing here (delegates to inner, which is nil in this test).
func TestControlTrackingSinkMirrorsControlState(t *testing.T) {
	a := &Agent{logger: zap.NewNop()}
	sink := a.trackingInputSink()

	if _, controlled := a.RemoteSupportState(); controlled {
		t.Fatal("controlled should start false")
	}
	sink.SetControlActive(true)
	if _, controlled := a.RemoteSupportState(); !controlled {
		t.Error("controlled should be true after SetControlActive(true)")
	}
	sink.SetControlActive(false)
	if _, controlled := a.RemoteSupportState(); controlled {
		t.Error("controlled should be false after SetControlActive(false)")
	}
	// Apply must not panic with a nil inner sink (non-windows: inputSink()=nil).
	sink.Apply(remotesupport.InputEvent{Event: "tap", X: 500, Y: 500})
}
