package tray

import "github.com/openidx/openidx/agent/internal/ipc"

// composeStatus is the tray's one-line status, from the sign-in state, whether
// a server is known (the device is enrolled, or --server was passed), and the
// service's answer over the pipe (nil when the service did not answer).
//
// It is a pure function so the wording can be tested without a tray. The
// not-enrolled case says what to do, because the tray now starts on a fresh
// install, before any enrolment, and "device: unknown" told the person
// nothing.
func composeStatus(signedIn, serverKnown bool, st *ipc.Status) string {
	// The device comes first and the person last: a device with nobody signed in
	// is working as designed (the tunnel carries its traffic under the device's
	// own identity), so "not signed in" is information, not the headline.
	person := T.SignedOutNote
	if signedIn {
		person = T.SignedIn
	}
	switch {
	case st != nil && st.Revoked:
		return T.DevRevoked + " · " + person
	case needsReEnrollment(st):
		return T.DevNotAccepted + " · " + person
	case st != nil && st.Enrolled:
		dev := T.DevEnrolled
		if st.ZitiEnrolled {
			dev += " · ziti"
		}
		if note := postureNote(st); note != "" {
			dev += " · " + note
		}
		return dev + " · " + person
	case st != nil && !st.Enrolled, !serverKnown:
		return T.NotEnrolledStatus
	}
	return T.DevUnknown + " · " + person
}
