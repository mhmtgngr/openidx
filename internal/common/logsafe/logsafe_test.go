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
