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
	case "windows":
		return c.checkWindows()
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

// checkWindows uses `netsh advfirewall show allprofiles state` and inspects the
// per-profile State lines. All profiles ON → pass; none ON → fail; a mix → warn.
func (c *FirewallCheck) checkWindows() *CheckResult {
	out, err := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("netsh advfirewall failed: %v", err),
			Details: map[string]interface{}{"os": "windows"},
		}
	}
	on, off := 0, 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "State") {
			continue
		}
		u := strings.ToUpper(line)
		if strings.Contains(u, "ON") {
			on++
		} else if strings.Contains(u, "OFF") {
			off++
		}
	}
	details := map[string]interface{}{
		"os": "windows", "method": "netsh", "profiles_on": on, "profiles_off": off,
	}
	switch {
	case on > 0 && off == 0:
		return &CheckResult{Status: StatusPass, Score: 1.0, Details: details, Message: "Windows Firewall is on for all profiles"}
	case on == 0:
		return &CheckResult{
			Status: StatusFail, Score: 0, Details: details,
			Message:     "Windows Firewall is off for all profiles",
			Remediation: "Enable Windows Firewall (`netsh advfirewall set allprofiles state on`).",
		}
	default:
		return &CheckResult{Status: StatusWarn, Score: 0.5, Details: details, Message: fmt.Sprintf("Windows Firewall on for %d profile(s), off for %d", on, off)}
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
