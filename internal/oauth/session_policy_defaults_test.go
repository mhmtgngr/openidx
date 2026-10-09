package oauth

import "testing"

// The compiled defaults are what an install runs until the Security tab sets
// something: they must bound concurrent sessions without ever refusing a
// sign-in.
func TestDefaultSessionPolicyBoundsConcurrentSessionsWithoutRefusing(t *testing.T) {
	p := DefaultSessionPolicy()
	if p.MaxConcurrentSessions <= 0 {
		t.Fatal("the default allows unlimited concurrent sessions")
	}
	if p.MaxConcurrentSessions < 5 {
		t.Fatalf("a cap of %d would cut off one person's console, phone, tray and privileged sessions", p.MaxConcurrentSessions)
	}
	if p.ConcurrentSessionStrategy != "terminate_oldest" {
		t.Fatalf("strategy %q can refuse a sign-in; the default must retire the oldest session instead", p.ConcurrentSessionStrategy)
	}
}
