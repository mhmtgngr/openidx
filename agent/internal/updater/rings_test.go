package updater

import (
	"math/rand"
	"testing"
	"time"
)

func TestFirstUpdateCheckIsJittered5to15Min(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		d := FirstCheckDelay(r)
		if d < 5*time.Minute || d >= 15*time.Minute {
			t.Fatalf("first check after %s, want within [5m, 15m)", d)
		}
		seen[d.Truncate(time.Minute)] = true
		n := NextCheckDelay(r)
		if n < 5*time.Hour+30*time.Minute || n >= 6*time.Hour+30*time.Minute {
			t.Fatalf("next check after %s, want 6h±30m", n)
		}
	}
	if len(seen) < 8 {
		t.Errorf("first-check delays bunch into %d minutes; a fleet would arrive together", len(seen))
	}
}

func TestDowngradeOnlyWhenServerAllows(t *testing.T) {
	pin := &Target{TargetVersion: "0.6.2"}
	if d := Decide("0.6.4", "0.6.2", pin); d != Stay {
		t.Errorf("a pin without allow_downgrade moved the device: %v", d)
	}
	pin.AllowDowngrade = true
	if d := Decide("0.6.4", "0.6.2", pin); d != Downgrade {
		t.Errorf("an allowed pin below the running build: %v, want Downgrade", d)
	}
	if d := Decide("0.6.1", "v0.6.2", pin); d != Upgrade {
		t.Errorf("a pin above the running build: %v, want Upgrade", d)
	}
	if d := Decide("0.6.2", "0.6.2", pin); d != Stay {
		t.Errorf("on the pin: %v", d)
	}
	if d := Decide("0.6.1", "0.6.5", pin); d != Stay {
		t.Errorf("a pinned device installed a build that is not the pin: %v", d)
	}
	if d := Decide("dev", "0.6.2", pin); d != Upgrade {
		t.Errorf("a dev build is older than anything: %v", d)
	}
	// Without a pin only forward, and never while paused.
	if d := Decide("0.6.4", "0.6.2", &Target{AllowDowngrade: true}); d != Stay {
		t.Errorf("an unpinned device downgraded: %v", d)
	}
	if d := Decide("0.6.1", "0.6.2", nil); d != Upgrade {
		t.Errorf("no target: %v", d)
	}
	if d := Decide("0.6.1", "0.6.2", &Target{Paused: true}); d != Stay {
		t.Errorf("a paused ring upgraded: %v", d)
	}
}

func TestVersionedManifestURL(t *testing.T) {
	got := VersionedManifestURL("https://github.com/o/r/releases/download/agent-latest/latest.json", "v0.6.2")
	if want := "https://github.com/o/r/releases/download/agent-v0.6.2/latest.json"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if VersionedManifestURL("https://updates.example/latest.json", "0.6.2") != "" {
		t.Error("a non-release URL produced a versioned one")
	}
}
