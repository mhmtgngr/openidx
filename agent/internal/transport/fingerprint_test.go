package transport

import (
	"strings"
	"testing"
)

// TestFingerprintIgnoresHostname: renaming a PC keeps its fingerprint, the
// value an older agent sent is offered as prev, and a machine with no id falls
// back to the old hostname-folded value with no prev.
func TestFingerprintIgnoresHostname(t *testing.T) {
	const guid = "6B29FC40-CA47-1067-B31D-00DD010662DA"
	a, prevA := fingerprints("win2:", "win:", guid, guid, "PC-ALICE")
	b, prevB := fingerprints("win2:", "win:", guid, guid, "PC-BOB")
	if a != b {
		t.Fatalf("a rename changed the fingerprint: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "win2:") || len(a) != len("win2:")+32 {
		t.Fatalf("unexpected stable fingerprint %q", a)
	}
	if prevA == prevB {
		t.Fatal("the legacy fingerprint folds the hostname and must differ between names")
	}
	if want := legacyFingerprint("win:", guid, "PC-ALICE"); prevA != want {
		t.Fatalf("prev = %q, want the old agent's value %q", prevA, want)
	}
	if fp, _ := fingerprints("win2:", "win:", strings.ToLower(guid), guid, "x"); fp != a {
		t.Fatal("the machine id is case-insensitive")
	}

	fp, prev := fingerprints("win2:", "win:", "", "", "PC-ALICE")
	if fp != legacyFingerprint("win:", "", "PC-ALICE") || prev != "" {
		t.Fatalf("no machine id: fp=%q prev=%q, want the legacy value and no prev", fp, prev)
	}
}
