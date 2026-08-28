package oauth

import "github.com/openidx/openidx/internal/identity"

// hasEnrolledPushApprover reports whether the user has an enabled push device
// that was auto-registered by a device enrollment (agent_id linked) — i.e. the
// FastPass "the enrolled phone is your authenticator" case. Such a device is a
// known-good approver, so login prefers push when one exists.
func hasEnrolledPushApprover(devices []identity.PushMFADevice) bool {
	for _, d := range devices {
		if d.Enabled && d.AgentID != "" {
			return true
		}
	}
	return false
}

// preferMethod returns methods with want moved to the front (order of the rest
// preserved). If want is absent the slice is returned unchanged. Pure helper so
// the login flow's method ordering stays reorder-only (never adds/removes).
func preferMethod(methods []string, want string) []string {
	idx := -1
	for i, m := range methods {
		if m == want {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return methods // absent, or already first
	}
	out := make([]string, 0, len(methods))
	out = append(out, want)
	for i, m := range methods {
		if i == idx {
			continue
		}
		out = append(out, m)
	}
	return out
}
