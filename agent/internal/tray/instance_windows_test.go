//go:build windows

package tray

import "testing"

func TestOnlyOneTrayPerSession(t *testing.T) {
	release, ok := acquireTrayMutex()
	if !ok {
		t.Fatal("the first tray could not claim the session")
	}
	if _, ok := acquireTrayMutex(); ok {
		t.Fatal("a second tray claimed the same session")
	}
	release()
	release2, ok := acquireTrayMutex()
	if !ok {
		t.Fatal("the slot was not free again after the first tray released it")
	}
	release2()
}
