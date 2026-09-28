package oauth

import (
	"strings"

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

// hasEnabledPushDevice reports whether a push challenge has anywhere to go. A
// device the user switched off cannot approve one (the approval gate refuses
// it), so it does not make push a factor the user has.
func hasEnabledPushDevice(devices []identity.PushMFADevice) bool {
	for _, d := range devices {
		if d.Enabled {
			return true
		}
	}
	return false
}
