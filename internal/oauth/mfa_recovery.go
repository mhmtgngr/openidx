package oauth

import (
	"strings"
	"time"

	"github.com/openidx/openidx/internal/identity"
)

// filterMethodsByRisk narrows the offered factors to what the risk engine
// allows for this login.
//
// The risk engine's lists name primary factors only, so a plain intersection
// used to drop the two recovery factors on every login: a user's backup codes
// and an administrator's bypass code were never offered, and a user whose
// phone was reinstalled had no way in. The recovery factors are therefore
// judged on their own terms:
//   - a bypass code is issued by an administrator for this user, so it stands
//     at every risk level;
//   - backup codes are the stand-in for the authenticator app, so they stand
//     wherever TOTP does, and go where TOTP goes.
//
// When no primary factor survives, the list is returned unchanged, as before,
// rather than leaving a user with a recovery factor alone.
func filterMethodsByRisk(methods, allowed []string) []string {
	if len(allowed) == 0 {
		return methods
	}
	primary := []string{}
	for _, m := range methods {
		if m != "backup" && m != "bypass" && hasMethod(allowed, m) {
			primary = append(primary, m)
		}
	}
	if len(primary) == 0 {
		return methods
	}
	out := primary
	if hasMethod(methods, "backup") && hasMethod(allowed, "totp") {
		out = append(out, "backup")
	}
	if hasMethod(methods, "bypass") {
		out = append(out, "bypass")
	}
	return out
}

// undeliverableEmailSuffixes are the domains no mail can reach: the names RFC
// 2606 and RFC 6761 reserve, plus ".local", which seeded and directory-synced
// test accounts use. Offering an email code to one of them sends the code
// nowhere and leaves the user waiting for it.
var undeliverableEmailSuffixes = []string{
	".local", ".localhost", ".test", ".invalid", ".example",
	"example.com", "example.net", "example.org",
}

// emailUndeliverable reports whether a one-time code sent to addr can never
// arrive.
func emailUndeliverable(addr string) bool {
	at := strings.LastIndex(addr, "@")
	if at < 1 || at == len(addr)-1 {
		return true
	}
	domain := strings.ToLower(strings.TrimSuffix(addr[at+1:], "."))
	for _, s := range undeliverableEmailSuffixes {
		if strings.HasPrefix(s, ".") {
			if strings.HasSuffix(domain, s) || domain == s[1:] {
				return true
			}
		} else if domain == s || strings.HasSuffix(domain, "."+s) {
			return true
		}
	}
	return false
}

// mfaPushUnseen tells a user signing in that their phone, their only second
// factor, has not been seen within PUSH_DEVICE_STALE_DAYS, and what they can
// use instead.
type mfaPushUnseen struct {
	// LastSeenAt is the most recent sighting of any of their push devices.
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// StaleDays is the window the phone fell outside of.
	StaleDays int `json:"stale_days"`
	// Disabled means no push device can be challenged at all: the system
	// disabled every one of them, so push is not offered.
	Disabled bool `json:"disabled,omitempty"`
	// Fallbacks are the other methods this challenge offers, in order.
	Fallbacks []string `json:"fallbacks"`
}

// pushUnseenFallbacks applies push liveness to the offered methods.
//
// A device unseen within the stale window is still a device: it is sent the
// challenge if push is chosen, because it may simply be a phone nobody has
// needed for a while. What changes is that it is never the only way in.
//
//   - Push moves behind every other offered method, so a user is not steered
//     to a phone nobody has seen.
//   - When push is the user's only primary factor (or every push device was
//     disabled by the system and the user has no other), the challenge also
//     offers an administrator's bypass code, whether or not one has been issued
//     yet: that is the way back in an administrator can hand them, and
//     VerifyBypassCode still checks it. Backup codes and email codes the user
//     has are already offered. The returned notice says so.
//
// Nothing is removed from the challenge and no challenge is skipped: the
// evaluation's Enabled verdict is the caller's, and a user whose push devices
// were all disabled is still challenged (with these fallbacks).
func pushUnseenFallbacks(methods []string, push identity.PushLiveness, staleAfter time.Duration) ([]string, *mfaPushUnseen) {
	if push.Fresh > 0 || (push.Stale == 0 && push.Suspended == 0) {
		return methods, nil
	}
	out := make([]string, 0, len(methods)+1)
	otherPrimary := false
	for _, m := range methods {
		if m == "push" {
			continue
		}
		if m != "backup" && m != "bypass" {
			otherPrimary = true
		}
		out = append(out, m)
	}
	if otherPrimary {
		// Another factor the user has stands in front; push goes last.
		if push.Offerable() {
			out = append(out, "push")
		}
		return out, nil
	}
	if !hasMethod(out, "bypass") {
		out = append(out, "bypass")
	}
	notice := &mfaPushUnseen{
		LastSeenAt: push.LastSeen,
		StaleDays:  int(staleAfter.Hours() / 24),
		Disabled:   !push.Offerable(),
		Fallbacks:  append([]string(nil), out...),
	}
	if push.Offerable() {
		out = append(out, "push")
	}
	return out, notice
}
