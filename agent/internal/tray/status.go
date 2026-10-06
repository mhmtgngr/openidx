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
	signPart := "Not signed in"
	if signedIn {
		signPart = "Signed in"
	}
	switch {
	case st != nil && st.Revoked:
		return signPart + " · device: REVOKED by an administrator"
	case st != nil && st.Enrolled:
		dev := "device: enrolled"
		if st.ZitiEnrolled {
			dev += " · ziti"
		}
		return signPart + " · " + dev
	case st != nil && !st.Enrolled, !serverKnown:
		return "Not enrolled · open your enrollment link"
	}
	return signPart + " · device: unknown"
}
