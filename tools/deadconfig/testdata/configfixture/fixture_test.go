package configfixture

import "testing"

// A test is not a reader. This file exists so the gate's own test can prove
// that: it touches Unread, and the census must still report Unread, because a
// field only a test consults is a field the product does not.
//
// This is the shape ENABLE_MFA had — a passing test asserting the flag parsed,
// while nothing in any binary ever consulted it.
func TestTouchesUnread(t *testing.T) {
	f := Fixture{Unread: "set by a test and by nothing else"}
	if f.Unread == "" {
		t.Fatal("unreachable; the assignment above is the whole point")
	}
	if (Section{Deep: "x", DeepUnread: "y"}).DeepUnread == "" {
		t.Fatal("unreachable")
	}
}
