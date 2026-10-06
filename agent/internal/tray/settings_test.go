package tray

import (
	"errors"
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/updater"
)

func TestShouldStart(t *testing.T) {
	cases := []struct {
		launchedForAutostart, userDisabled, want bool
	}{
		{true, false, true},  // Run key, autostart on: runs
		{true, true, false},  // Run key, autostart off: exits
		{false, true, true},  // Start menu, autostart off: runs anyway
		{false, false, true}, // Start menu, autostart on: runs
	}
	for _, tc := range cases {
		if got := shouldStart(tc.launchedForAutostart, tc.userDisabled); got != tc.want {
			t.Fatalf("shouldStart(%v, %v) = %v, want %v", tc.launchedForAutostart, tc.userDisabled, got, tc.want)
		}
	}
}

func TestUpdateMessage(t *testing.T) {
	if msg := updateMessage("1.40.0", "", nil, nil); !strings.Contains(msg, "not configured") || !strings.Contains(msg, "1.40.0") {
		t.Fatalf("no manifest: %q", msg)
	}
	if msg := updateMessage("1.40.0", "https://u.test/m.json", nil, errors.New("tls: bad certificate")); !strings.Contains(msg, "bad certificate") {
		t.Fatalf("error: %q", msg)
	}
	newer := &updater.Manifest{Version: "1.41.0"}
	if msg := updateMessage("1.40.0", "https://u.test/m.json", newer, nil); !strings.Contains(msg, "1.41.0 is available") || !strings.Contains(msg, "six hours") {
		t.Fatalf("newer: %q", msg)
	}
	same := &updater.Manifest{Version: "1.40.0"}
	if msg := updateMessage("1.40.0", "https://u.test/m.json", same, nil); !strings.Contains(msg, "up to date") {
		t.Fatalf("same: %q", msg)
	}
	older := &updater.Manifest{Version: "1.39.0"}
	if msg := updateMessage("1.40.0", "https://u.test/m.json", older, nil); !strings.Contains(msg, "up to date") {
		t.Fatalf("older manifest is not an update: %q", msg)
	}
}
