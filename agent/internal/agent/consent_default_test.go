package agent

import "testing"

// TestWithNoPromptAnAttendedSessionIsDenied: a process that cannot ask the
// person at the device cannot say they allowed it. It used to grant.
func TestWithNoPromptAnAttendedSessionIsDenied(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s1", ConsentRequired: true, ConsentStatus: "pending"})
	if len(m.sent) != 1 || m.sent[0] != "s1:deny" {
		t.Fatalf("with no decider the session must be denied, got %v", m.sent)
	}
}

// TestAnUnattendedSessionNeedsNoConsentAndStreams: consent_required false is
// the administrator's unattended choice; it is not touched by the default.
func TestAnUnattendedSessionNeedsNoConsentAndStreams(t *testing.T) {
	m := &consentMock{}
	a := newTestAgent(m)
	a.processRemoteSupportConsent(&RemoteSupportBlock{SessionID: "s2", ConsentRequired: false, ConsentStatus: ""})
	if len(m.sent) != 0 {
		t.Fatalf("an unattended session sends no consent decision, got %v", m.sent)
	}
}
