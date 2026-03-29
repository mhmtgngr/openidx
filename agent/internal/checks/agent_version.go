package checks

import (
	"context"
	"fmt"
)

// AgentVersion is the version of the running agent binary. It defaults to
// "dev" and can be overridden at build time via:
//
//	-ldflags "-X github.com/openidx/openidx/agent/internal/checks.AgentVersion=1.2.3"
var AgentVersion = "dev"

// AgentVersionCheck verifies that the running agent meets a minimum version
// requirement supplied via params["min_version"].
//
// If min_version is not provided or is empty the check always passes.
// Version comparison is performed with the same logic used by OSVersionCheck.
type AgentVersionCheck struct{}

// Name implements Check.
func (c *AgentVersionCheck) Name() string { return "agent_version" }

// Run implements Check.
func (c *AgentVersionCheck) Run(_ context.Context, params map[string]interface{}) *CheckResult {
	current := AgentVersion

	details := map[string]interface{}{
		"agent_version": current,
	}

	minVersion, _ := params["min_version"].(string)
	if minVersion == "" {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: fmt.Sprintf("agent version: %s (no minimum required)", current),
		}
	}

	details["min_version"] = minVersion

	// "dev" builds are treated as pre-release and always fail a version gate.
	if current == "dev" {
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     fmt.Sprintf("agent is running a development build (version=dev); minimum required is %s", minVersion),
			Remediation: fmt.Sprintf("Upgrade the agent to at least version %s.", minVersion),
		}
	}

	cmp := compareVersions(current, minVersion)
	if cmp < 0 {
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     fmt.Sprintf("agent version %s is below minimum required %s", current, minVersion),
			Remediation: fmt.Sprintf("Upgrade the agent to at least version %s.", minVersion),
		}
	}

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Details: details,
		Message: fmt.Sprintf("agent version %s meets minimum requirement %s", current, minVersion),
	}
}
