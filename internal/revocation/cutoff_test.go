package revocation

import (
	"testing"
	"time"
)

// The per-user marker compared whole seconds with `<=`, so a token minted in
// the second of a logout was refused whichever side of the logout it fell on:
// a user who signed out and back in inside one second was rejected. The fix
// adds microseconds on both sides -- and must refuse everything the old rule
// refused that could have come BEFORE the revocation. These pin both halves.

const sec = int64(1_750_000_000)

func us(fraction int64) int64 { return sec*1e6 + fraction }

func TestAPreciseCutoffSeparatesTokensInsideItsSecond(t *testing.T) {
	cutoff, err := ParseMarker(MarkerValue(time.Unix(sec, 500_000_000)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		token IssuedAt
		want  bool
	}{
		{"granted before the cutoff, same second", IssuedAt{Seconds: sec, GrantedMicros: us(499_999)}, true},
		{"granted at the cutoff's microsecond", IssuedAt{Seconds: sec, GrantedMicros: us(500_000)}, true},
		{"granted after the cutoff, same second", IssuedAt{Seconds: sec, GrantedMicros: us(500_001)}, false},
		// Whole seconds cannot say which side of the cutoff they fell on.
		{"an older token with iat only, same second", IssuedAt{Seconds: sec}, true},
		{"an older token with iat only, next second", IssuedAt{Seconds: sec + 1}, false},
		// A code issued before the logout and redeemed after it: the token's
		// iat is later, the grant is not, and the grant decides.
		{"minted next second from a grant before the cutoff", IssuedAt{Seconds: sec + 1, GrantedMicros: us(400_000)}, true},
		// A claim that lies after its own iat second is not believed.
		{"a grant time past the end of the iat second", IssuedAt{Seconds: sec, GrantedMicros: us(1_600_000)}, true},
		{"no iat at all", IssuedAt{GrantedMicros: us(400_000)}, false},
	} {
		if got := cutoff.Revokes(tc.token); got != tc.want {
			t.Errorf("%s: Revokes = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A marker written by a release before this one is whole seconds. It says the
// revocation happened somewhere in that second, so it reaches to the END of
// it: a precise token from the same second is refused even if it was minted
// late in the second -- exactly what the old rule did.
func TestAWholeSecondMarkerRevokesTheWholeSecond(t *testing.T) {
	cutoff, err := ParseMarker("1750000000")
	if err != nil {
		t.Fatal(err)
	}
	if !cutoff.Revokes(IssuedAt{Seconds: sec, GrantedMicros: us(999_999)}) {
		t.Error("a whole-second marker let a token from its own second through")
	}
	if !cutoff.Revokes(IssuedAt{Seconds: sec}) {
		t.Error("a whole-second marker let a whole-second token from its own second through")
	}
	if cutoff.Revokes(IssuedAt{Seconds: sec + 1, GrantedMicros: us(1_000_000)}) {
		t.Error("a whole-second marker revoked a token from the next second")
	}
}

func TestMarkerValueRoundTripsToTheMicrosecond(t *testing.T) {
	at := time.Unix(sec, 123_456_789)
	v := MarkerValue(at)
	if v != "1750000000.123456" {
		t.Fatalf("MarkerValue = %q, want seconds.microseconds", v)
	}
	cutoff, err := ParseMarker(v)
	if err != nil {
		t.Fatal(err)
	}
	if cutoff.lastRevokedMicros != at.UnixMicro() {
		t.Fatalf("parsed %d, want %d", cutoff.lastRevokedMicros, at.UnixMicro())
	}
	// Up to nine fraction digits are read; past the sixth they are dropped.
	if c, err := ParseMarker("1750000000.123456789"); err != nil || c.lastRevokedMicros != us(123_456) {
		t.Fatalf("nanosecond marker: %v %v", c, err)
	}
	if c, err := ParseMarker("1750000000.5"); err != nil || c.lastRevokedMicros != us(500_000) {
		t.Fatalf("short fraction: %v %v", c, err)
	}
}

// Unreadable is an error, never "nothing revoked": the caller fails closed.
func TestAMalformedMarkerIsAnError(t *testing.T) {
	for _, v := range []string{"", "abc", "1750000000.", "1750000000.x", "1750000000.-5",
		"1750000000.1234567890", ".5", "1750000000.5.5"} {
		if _, err := ParseMarker(v); err == nil {
			t.Errorf("ParseMarker(%q) accepted a malformed marker", v)
		}
	}
}
