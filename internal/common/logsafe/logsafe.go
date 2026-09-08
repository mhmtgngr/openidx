// Package logsafe neutralises attacker-controlled values before they reach a
// log line.
//
// Why it exists in one place: five packages had each grown their own copy of
// this function — internal/oauth/stepup.go and internal/governance/revocation.go
// and internal/access/ziti_ai.go as sanitizeForLog, internal/admin and
// internal/credentials as sanitizeLogValue — and they did not agree. Four
// stripped only CR and LF; one (credentials) stripped every control character.
// None bounded length. A security-relevant function with five implementations
// and two behaviours is a function nobody can reason about, and the weakest
// copy is the one that decides what an attacker can do.
//
// What the risk actually is. An earlier version of this comment said zap's
// console encoder writes a newline raw while its JSON encoder escapes one, so a
// forged log line was possible under the console encoder. That is wrong, and
// naming the wrong mechanism is worse than naming none: it invites the fix
// "just use the JSON encoder", which fixes nothing. encoder_test.go measures
// what the two encoders really do, so the claim in this comment stays checkable:
//
//   - A zap FIELD is escaped by BOTH encoders. The console encoder delegates
//     fields to a JSON encoder, so a newline comes out as \n and an ANSI
//     escape as \u001b under either. A tainted value passed as a field cannot
//     forge a line.
//   - A zap MESSAGE is escaped by the JSON encoder and written RAW by the
//     console encoder. Interpolating a tainted value into the message — the
//     fmt.Sprintf("... %s", userInput) shape — is therefore the one way to write
//     a second, fully attacker-authored line, complete with a forged FATAL
//     level, into a development or staging log. no_interpolated_message_test.go
//     is the guard that keeps that shape out of the tree.
//
// So a field is not a line-forging vector, and three reasons to clean one
// remain:
//
//   - Length. A megabyte of client_id in every warning is a cheap way to fill a
//     disk or bury the line that mattered, and no encoder bounds it.
//   - Sinks that are not zap. The log is shipped onward — to Elasticsearch, to a
//     SIEM, to a terminal running `docker logs` — and the escaping is the
//     encoder's, not the value's. Cleaning at the source is the only form that
//     survives the next hop.
//   - Reachability is not theoretical: a percent-encoded %0A in a request target
//     arrives in c.Request.URL.Path as a real newline (encoder_test.go proves
//     this too), so "the path" is attacker-controlled text, not a route name.
//
// So: strip every control character, cap the length, and say in one place what
// "safe to log" means. CodeQL's "Log entries created from user input" rule
// flagged eleven sites in the assignment- and ABAC-decision recorders and, later,
// the tenant resolver's cross-org warning; those now go through here.
package logsafe

import (
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"
)

// MaxLen bounds a logged value. 256 bytes is longer than every identifier this
// platform legitimately logs (a UUID is 36, an OAuth client_id is capped at 255
// by the column) and short enough that a hostile value cannot bury the entry it
// is attached to.
const MaxLen = 256

// truncationMarker is appended to a value that was cut, so a reader can tell a
// truncated value from a short one — silently shortening an identifier makes
// two different values look identical in the log.
const truncationMarker = "…[truncated]"

// Clean returns s with every control character removed and the result bounded
// to MaxLen. Control characters go rather than get escaped because there is no
// legitimate reason for one to appear in an identifier, and removing them means
// the result is safe under EVERY encoder rather than only the ones that escape.
func Clean(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		// C0 controls (including CR, LF and TAB), DEL, and the C1 range that
		// some terminals still interpret.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		// Invalid UTF-8 decodes to RuneError one byte at a time. A raw 0x9b
		// byte — a C1 control, written by anything that is not UTF-8 — arrives
		// here as RuneError rather than as 0x9b, so dropping only the C1 range
		// above would let it through re-encoded. A value that is not valid
		// UTF-8 has no business in a log line either way. This also drops a
		// legitimately encoded U+FFFD, which is a price worth paying.
		if r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if len(cleaned) > MaxLen {
		return cleaned[:MaxLen] + truncationMarker
	}
	return cleaned
}

// String is zap.String with the value cleaned. Use it for anything that reached
// the process from outside: a query parameter, a header, a form field, a value
// read back from a token or a session.
func String(key, value string) zap.Field {
	return zap.String(key, Clean(value))
}

// MaxIDLen bounds an externally supplied identifier. A UUID is 36 characters and
// a W3C traceparent is 55; 128 leaves room for a caller's own scheme without
// leaving room for a payload.
const MaxIDLen = 128

// PlausibleID reports whether a value that arrived from outside may be used as
// an identifier the platform adopts: echoed back in a response header, stored on
// the request context, and stamped on every log line for the request.
//
// Three middlewares read X-Request-ID and one reads X-Correlation-ID, and before
// this existed all four took whatever arrived. That means the CLIENT chose what
// an operator greps for during an incident, how long every log line for the
// request would be, and what came back in the response — a caller sending five
// kilobytes got five kilobytes back and five kilobytes per entry.
//
// Note what this is NOT: it is not Clean. A rejected id must be REPLACED, not
// cleaned into shape. An id that was quietly rewritten still ties one request's
// entries together but no longer matches what the caller kept, which is the one
// job a correlation id has; handing back an id the caller does not recognise is
// the honest failure. So this answers yes or no, and the caller mints a fresh
// UUID on no.
//
// The accepted set is what tracing systems actually emit: ASCII letters and
// digits plus - _ . : — enough for a UUID, a traceparent, and a vendor scheme.
func PlausibleID(s string) bool {
	if s == "" || len(s) > MaxIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}
