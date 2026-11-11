package access

import (
	"fmt"
	"testing"
)

// A pause holds every device, a pin becomes the target and allows the
// downgrade to it, and the channel picks the feed.
func TestUpdateTargetHonoursPauseAndPin(t *testing.T) {
	b := updateTarget("agent-1", defaultAgentUpdateSettings())
	if b.Paused || b.TargetVersion != "" || b.AllowDowngrade || b.Channel != "stable" || b.ManifestURL == "" {
		t.Fatalf("defaults: %+v", b)
	}
	b = updateTarget("agent-1", agentUpdateSettings{Channel: "stable", RolloutPercent: 100, Paused: true})
	if !b.Paused {
		t.Error("a paused ring did not hold the device")
	}
	b = updateTarget("agent-1", agentUpdateSettings{Channel: "beta", RolloutPercent: 100, PinVersion: "0.6.2"})
	if b.TargetVersion != "0.6.2" || !b.AllowDowngrade || b.Channel != "beta" || b.ManifestURL == channelManifestURL("stable") {
		t.Errorf("pinned beta ring: %+v", b)
	}
	if b := updateTarget("agent-1", agentUpdateSettings{Channel: "nonsense", RolloutPercent: 100}); b.Channel != "stable" {
		t.Errorf("an unknown channel was served as %q", b.Channel)
	}
}

// A device's place in the ring is a function of its id alone, the share of a
// large fleet tracks the percentage, and raising it only adds devices.
func TestRolloutPercentIsDeterministicPerAgent(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("agent-%d", i)
		if inRollout(id, 30) != inRollout(id, 30) {
			t.Fatalf("%s moved between two checks", id)
		}
		if inRollout(id, 30) && !inRollout(id, 60) {
			t.Fatalf("%s left the ring when it grew", id)
		}
		if inRollout(id, 0) || !inRollout(id, 100) {
			t.Fatalf("0%% / 100%% are not none / all for %s", id)
		}
	}
	in := 0
	for i := 0; i < 2000; i++ {
		if inRollout(fmt.Sprintf("agent-%d", i), 25) {
			in++
		}
	}
	if in < 400 || in > 600 {
		t.Errorf("25%% rollout reached %d of 2000", in)
	}
}

func TestValidUpdateSettings(t *testing.T) {
	ok := agentUpdateSettings{Channel: "stable", RolloutPercent: 50, PinVersion: "v0.6.3"}
	if msg := validUpdateSettings(ok); msg != "" {
		t.Fatal(msg)
	}
	for _, bad := range []agentUpdateSettings{
		{Channel: "nightly", RolloutPercent: 10},
		{Channel: "stable", RolloutPercent: 101},
		{Channel: "stable", RolloutPercent: -1},
		{Channel: "stable", RolloutPercent: 1, PinVersion: "1.0; rm -rf"},
	} {
		if validUpdateSettings(bad) == "" {
			t.Errorf("accepted %+v", bad)
		}
	}
}
