//go:build windows

package tray

import "testing"

// TestTheAutostartPreferenceRoundTrips writes the preference for the test's
// own user and reads it back both ways, then restores "on".
func TestTheAutostartPreferenceRoundTrips(t *testing.T) {
	t.Cleanup(func() { _ = setAutostart(true) })
	if err := setAutostart(false); err != nil {
		t.Fatalf("setAutostart(false): %v", err)
	}
	if !AutostartDisabled() {
		t.Fatal("after turning it off, AutostartDisabled must be true")
	}
	if err := setAutostart(true); err != nil {
		t.Fatalf("setAutostart(true): %v", err)
	}
	if AutostartDisabled() {
		t.Fatal("after turning it on, AutostartDisabled must be false")
	}
}
