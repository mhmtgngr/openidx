package checks

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// FirewallCheck verifies that a host-based firewall is active on the device.
//
// Linux: tries `ufw status` first and looks for "Status: active". Falls back
// to `iptables -L` and checks whether there are any non-default rules present.
//
// macOS: runs `pfctl -s info` and looks for "Status: Enabled".
//
// All other operating systems receive a StatusWarn result.
type FirewallCheck struct{}

// Name implements Check.
func (c *FirewallCheck) Name() string { return "firewall" }

// Run implements Check.
func (c *FirewallCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkMacOS()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("firewall check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

func (c *FirewallCheck) checkLinux() *CheckResult {
	// Try ufw first.
	if out, err := exec.Command("ufw", "status").Output(); err == nil {
		active := strings.Contains(string(out), "Status: active")
		details := map[string]interface{}{
			"os":     "linux",
			"method": "ufw",
		}
		if active {
			return &CheckResult{
				Status:  StatusPass,
				Score:   1.0,
				Details: details,
				Message: "firewall is active (ufw)",
			}
		}
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     "ufw firewall is inactive",
			Remediation: "Enable the firewall with `sudo ufw enable`.",
		}
	}

	// Fall back to iptables.
	out, err := exec.Command("iptables", "-L").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("could not check firewall status via ufw or iptables: %v", err),
			Details: map[string]interface{}{"os": "linux"},
		}
	}

	details := map[string]interface{}{
		"os":     "linux",
		"method": "iptables",
	}

	// A minimal iptables setup with only the default ACCEPT policies is
	// effectively an open firewall. Heuristic: if there are more than 3
	// non-empty lines after the header lines, assume rules are present.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	rulesPresent := len(lines) > 3
	if rulesPresent {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "iptables rules are present",
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "no iptables rules found; firewall may not be configured",
		Remediation: "Configure iptables rules or install and enable ufw.",
	}
}

func (c *FirewallCheck) checkMacOS() *CheckResult {
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		// pfctl may exit non-zero even when returning output.
		if len(out) == 0 {
			return &CheckResult{
				Status:  StatusError,
				Score:   0,
				Message: fmt.Sprintf("pfctl failed: %v", err),
				Details: map[string]interface{}{"os": "darwin"},
			}
		}
	}

	enabled := strings.Contains(string(out), "Status: Enabled")
	details := map[string]interface{}{
		"os":     "darwin",
		"method": "pfctl",
	}

	if enabled {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "pf firewall is enabled",
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "pf firewall is not enabled",
		Remediation: "Enable the firewall in System Settings > Network > Firewall, or run `sudo pfctl -e`.",
	}
}
