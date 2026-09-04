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
// What the risk actually is: zap's JSON encoder escapes a newline to \n, so a
// forged log line is not possible there. Its CONSOLE encoder does not, and that
// is the encoder a development deployment runs (LOG_LEVEL=debug, APP_ENV=
// development in the reference compose stack). A client_id read straight from
// a query parameter can therefore write a second line into the log of a
// development or staging box and put whatever it likes in it. Length matters
// too: a megabyte of client_id in every warning is a cheap way to fill a disk
// or bury the line that mattered.
//
// So: strip every control character, cap the length, and say in one place what
// "safe to log" means. CodeQL's "Log entries created from user input" rule
// flagged eleven sites in the assignment- and ABAC-decision recorders; those
// now go through here.
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
