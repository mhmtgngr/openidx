//go:build !windows

package main

import "testing"

// TestALinkIsEnrolledInThisProcessOffWindows: no elevation hand-off exists
// outside Windows, so the link runs here. The Windows half (a UAC prompt)
// cannot run in a test.
func TestALinkIsEnrolledInThisProcessOffWindows(t *testing.T) {
	handedOff, err := elevateForDeepLink("openidx://enroll?code=abc&server=https://openidx.test")
	if handedOff || err != nil {
		t.Fatalf("handedOff=%v err=%v", handedOff, err)
	}
}
