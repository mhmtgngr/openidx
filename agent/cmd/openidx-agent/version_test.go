package main

import (
	"context"
	"testing"

	"github.com/openidx/openidx/agent/internal/checks"
)

// TestTheAgentVersionCheckSeesTheBuildVersion: a binary built with
// -X main.Version=v1.40.0 must answer a min_version gate with 1.40.0, not with
// "dev" (which the check treats as a pre-release and always fails).
func TestTheAgentVersionCheckSeesTheBuildVersion(t *testing.T) {
	origVersion, origCheck := Version, checks.AgentVersion
	t.Cleanup(func() { Version, checks.AgentVersion = origVersion, origCheck })

	Version, checks.AgentVersion = "v1.40.0", "dev"
	wireBuildVersion()
	if checks.AgentVersion != "1.40.0" {
		t.Fatalf("checks.AgentVersion = %q, want 1.40.0", checks.AgentVersion)
	}

	res := (&checks.AgentVersionCheck{}).Run(context.Background(), map[string]interface{}{"min_version": "1.39.0"})
	if res.Status != checks.StatusPass {
		t.Fatalf("a 1.40.0 agent must pass a 1.39.0 minimum; got %s: %s", res.Status, res.Message)
	}
	res = (&checks.AgentVersionCheck{}).Run(context.Background(), map[string]interface{}{"min_version": "1.41.0"})
	if res.Status != checks.StatusFail {
		t.Fatalf("a 1.40.0 agent must fail a 1.41.0 minimum; got %s: %s", res.Status, res.Message)
	}
}

// TestADevBuildStaysDev: with nothing stamped, the check still says "dev", so
// an unversioned local build keeps failing a version gate rather than passing
// it by accident.
func TestADevBuildStaysDev(t *testing.T) {
	origVersion, origCheck := Version, checks.AgentVersion
	t.Cleanup(func() { Version, checks.AgentVersion = origVersion, origCheck })

	Version, checks.AgentVersion = "dev", "dev"
	wireBuildVersion()
	if checks.AgentVersion != "dev" {
		t.Fatalf("checks.AgentVersion = %q, want dev", checks.AgentVersion)
	}
}

// TestAnExplicitCheckVersionWins: a build that stamps checks.AgentVersion
// directly is not overwritten by main.Version.
func TestAnExplicitCheckVersionWins(t *testing.T) {
	origVersion, origCheck := Version, checks.AgentVersion
	t.Cleanup(func() { Version, checks.AgentVersion = origVersion, origCheck })

	Version, checks.AgentVersion = "v9.9.9", "1.2.3"
	wireBuildVersion()
	if checks.AgentVersion != "1.2.3" {
		t.Fatalf("checks.AgentVersion = %q, want the explicit 1.2.3", checks.AgentVersion)
	}
}
