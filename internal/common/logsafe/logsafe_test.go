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
