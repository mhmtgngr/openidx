package logsafe

import (
	"strings"
	"testing"
)

// A forged log line is the whole point: a value carrying CR or LF must not be
// able to end the entry it is in and start one of its own.
func TestCleanRemovesLineBreaks(t *testing.T) {
	for _, in := range []string{
		"admin-console\nlevel=info msg=\"user promoted to super_admin\"",
		"admin-console\r\nlevel=info",
		"admin\rconsole",
	} {
		got := Clean(in)
		if strings.ContainsAny(got, "\n\r") {
			t.Errorf("Clean(%q) = %q, still contains a line break", in, got)
		}
	}
}

// Control characters other than CR/LF matter too: a terminal reading a console
// log will act on an escape sequence, and NUL truncates in some consumers. The
// bare 0x9b byte is deliberate: it is a C1 control that is also invalid UTF-8,
// so it exercises the RuneError branch rather than the C1 range check.
func TestCleanRemovesEveryControlCharacter(t *testing.T) {
	in := "id\x00\x07\x1b[31m\x7f\x9bvalue\t"
	got := Clean(in)
	if got != "id[31mvalue" {
		t.Errorf("Clean(%q) = %q, want %q", in, got, "id[31mvalue")
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Errorf("Clean left control character %q in %q", r, got)
		}
	}
}

// An unbounded value in every warning is a way to fill a disk and to bury the
// line that mattered.
func TestCleanBoundsLength(t *testing.T) {
	got := Clean(strings.Repeat("a", MaxLen*4))
	if len(got) != MaxLen+len(truncationMarker) {
		t.Errorf("len(Clean(long)) = %d, want %d", len(got), MaxLen+len(truncationMarker))
	}
	if !strings.HasSuffix(got, truncationMarker) {
		t.Errorf("a truncated value must say so; got %q", got[len(got)-20:])
	}
}

// Truncation must be visible, or two different identifiers that share a prefix
// read as the same value.
func TestTruncationIsDistinguishableFromAShortValue(t *testing.T) {
	short := Clean(strings.Repeat("a", MaxLen))
	long := Clean(strings.Repeat("a", MaxLen+1))
	if short == long {
		t.Error("a value at the limit and a value over it produced the same output")
	}
	if strings.HasSuffix(short, truncationMarker) {
		t.Error("a value that fits must not be marked truncated")
	}
}

// The common case must survive untouched, or callers will stop using this.
func TestCleanLeavesOrdinaryValuesAlone(t *testing.T) {
	for _, in := range []string{
		"admin-console",
		"3f1b8c2e-0000-4a1d-9c3f-d8f462084350",
		"user@example.com",
		"Ünïcødé kullanıcı",
		"",
	} {
		if got := Clean(in); got != in {
			t.Errorf("Clean(%q) = %q, want it unchanged", in, got)
		}
	}
}

// String is the field constructor callers actually use; it must clean.
func TestStringCleansTheValue(t *testing.T) {
	f := String("client_id", "evil\nid")
	if f.String != "evilid" {
		t.Errorf("String() carried %q, want %q", f.String, "evilid")
	}
	if f.Key != "client_id" {
		t.Errorf("String() key = %q, want client_id", f.Key)
	}
}

// PlausibleID decides what four middlewares adopt from a client, so the boundary
// is worth spelling out rather than leaving to the reader of the loop.
func TestPlausibleID(t *testing.T) {
	accept := []string{
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",                    // UUID
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // W3C traceparent
		"svc.api.7a1f_2b", // a vendor scheme
		"req:12345",
		"a",
		strings.Repeat("a", MaxIDLen),
	}
	for _, s := range accept {
		if !PlausibleID(s) {
			t.Errorf("PlausibleID(%q) = false, want true — a legitimate correlation id was thrown away", s)
		}
	}

	reject := map[string]string{
		"":                              "empty",
		strings.Repeat("a", MaxIDLen+1): "one over the bound",
		strings.Repeat("A", 5000):       "the measured five-kilobyte case",
		"abc\ndef":                      "a line break",
		"abc\r\ndef":                    "a CRLF",
		"abc def":                       "a space",
		"abc\x1b[2Jdef":                 "an ANSI escape",
		"<script>alert(1)</script>":     "markup",
		"id/../../etc/passwd":           "a path traversal, in case an id is ever used as one",
		"id%0Aforged":                   "a percent-encoded newline",
		"tenant=acme&role=admin":        "query syntax",
		"ünïcode":                       "non-ASCII, which no tracing system emits",
	}
	for s, why := range reject {
		if PlausibleID(s) {
			t.Errorf("PlausibleID(%q) = true, want false (%s)", s, why)
		}
	}
}

// TestCleanIsNotReplaceAllOfCRLF exists because of a trap with a name.
//
// CodeQL's Go log-injection query recognises exactly two sanitizers
// (go/ql/lib/semmle/go/security/LogInjectionCustomizations.qll):
//
//   - ReplaceSanitizer -- a strings.ReplaceAll whose replaced string is "\r" or "\n"
//   - SafeFormatArgumentSanitizer -- an argument formatted with %q
//
// Clean is neither. It uses strings.Map, so the query follows taint straight
// through it and raises go/log-injection on every call site that uses this
// package -- nine of them at the time of writing, all on lines that ARE
// sanitised. The alerts are recorded in docs/evidence/codeql-triage.md.
//
// The tempting fix is to rewrite Clean as strings.ReplaceAll for CR and LF,
// which would make the scanner quiet. It would also make this function the
// WEAKER of the two implementations this package was created to unify: the
// package comment records that four of the five copies it replaced "stripped
// only CR and LF", and that the weakest copy is the one that decides what an
// attacker can do. A tab still breaks a TSV log line, an ANSI escape still
// reprograms the terminal reading it, and a NUL still truncates in some
// consumers.
//
// So the assertion is on the behaviour a ReplaceAll rewrite would lose. If this
// test goes red because somebody made the scanner happy, the scanner was made
// happy at the cost of the control.
func TestCleanIsNotReplaceAllOfCRLF(t *testing.T) {
	crlfOnly := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		return strings.ReplaceAll(s, "\n", "")
	}

	for _, tc := range []struct {
		in   string
		what string
	}{
		{"a\tb", "a tab, which ends a field in a TSV-shaped log line"},
		{"a\x1b[2Jb", "an ANSI escape, which a terminal reading the log acts on"},
		{"a\x00b", "a NUL, which truncates in some consumers"},
		{"a\x7fb", "a DEL"},
		{"a\x9bb", "a raw C1 control that is also invalid UTF-8"},
	} {
		if crlfOnly(tc.in) == Clean(tc.in) {
			t.Errorf("Clean(%q) is indistinguishable from a CR/LF-only ReplaceAll — %s survived; "+
				"see this test's comment before matching CodeQL's sanitizer shape", tc.in, tc.what)
		}
	}
}

// A Semgrep finding on JSONBody named CWE-502 and said "use a concrete struct
// type instead". The named CWE does not apply: Go's encoding/json produces only
// map[string]interface{}, []interface{}, string, float64, bool and nil, so there
// is no gadget chain and no arbitrary type to instantiate. And a concrete struct
// is not available anyway — the whole job is redacting bodies whose shape is
// unknown.
//
// The concern underneath it does apply, and it was introduced by moving
// redaction ahead of truncation: this function now sees the FULL body, and
// decoding into an interface{} tree costs several times the input. So the input
// is bounded, and this is where that is checked. The depth case is here for the
// opposite reason: to record that encoding/json already refuses beyond 10,000
// levels, so the recursion in redactValues needs no bound of its own.
func TestJSONBodyBoundsWhatItParses(t *testing.T) {
	big := `{"password":"hunter2","filler":"` + strings.Repeat("x", MaxParsedBodyBytes) + `"}`
	got := JSONBody(big, nil)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "xxxx") {
		t.Fatalf("an oversized body was parsed and echoed: %.120q", got)
	}
	if !strings.Contains(got, "parse limit") {
		t.Fatalf("an oversized body should say why it was withheld, got %q", got)
	}

	// Just under the limit still parses and still redacts, or the bound has eaten
	// the feature.
	ok := `{"password":"hunter2","note":"` + strings.Repeat("y", 1024) + `"}`
	got = JSONBody(ok, nil)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("a body within the limit was not redacted: %.120q", got)
	}
	if !strings.Contains(got, "yyyy") {
		t.Fatalf("a body within the limit lost its non-secret content: %.120q", got)
	}

	// Deep nesting is the parser's problem, not this function's, and it declines
	// it rather than recursing.
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	if got := JSONBody(deep, nil); !strings.Contains(got, "redacted") {
		t.Fatalf("deeply nested input should be withheld, got %.80q", got)
	}
}
