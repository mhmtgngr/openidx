package checks

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// antivirusProcesses is the list of well-known AV process names checked on Linux.
var antivirusProcesses = []string{
	"clamd",         // ClamAV daemon
	"freshclam",     // ClamAV updater
	"falcon-sensor", // CrowdStrike Falcon
	"cs-falcon",     // CrowdStrike Falcon (alternate)
	"crowdstrike",   // CrowdStrike generic
	"xagt",          // FireEye/Trellix agent
	"ds_agent",      // Trend Micro Deep Security
	"symcfgd",       // Symantec/Broadcom
	"savd",          // Sophos Anti-Virus daemon
	"sfc",           // Sophos Firewall/Intercept X
}

// AntivirusCheck verifies that antivirus software is active on the device.
//
// Linux: scans /proc for well-known AV process names.
//
// macOS: checks XProtect by verifying that its definition plist is present and
// readable.
//
// All other operating systems receive a StatusWarn result.
type AntivirusCheck struct{}

// Name implements Check.
func (c *AntivirusCheck) Name() string { return "antivirus" }

// Run implements Check.
func (c *AntivirusCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkMacOS()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("antivirus check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

func (c *AntivirusCheck) checkLinux() *CheckResult {
	running, err := listRunningProcesses()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("failed to list running processes: %v", err),
			Details: map[string]interface{}{"os": "linux"},
		}
	}

	found := make([]string, 0)
	for _, avProc := range antivirusProcesses {
		if isRunning(running, avProc) {
			found = append(found, avProc)
		}
	}

	details := map[string]interface{}{
		"os":    "linux",
		"found": found,
	}

	if len(found) > 0 {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: fmt.Sprintf("antivirus process(es) detected: %s", strings.Join(found, ", ")),
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "no known antivirus processes found",
		Remediation: "Install and start an antivirus solution (e.g. ClamAV: `sudo apt install clamav clamav-daemon && sudo systemctl start clamav-daemon`).",
	}
}

func (c *AntivirusCheck) checkMacOS() *CheckResult {
	// XProtect is Apple's built-in malware protection. Its definitions are
	// stored in a known path. Checking for the presence of the plist confirms
	// XProtect is available (it ships with macOS and cannot be fully uninstalled
	// without compromising the OS).
	out, err := exec.Command("defaults", "read",
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta",
		"Version").Output()

	details := map[string]interface{}{
		"os":     "darwin",
		"method": "xprotect",
	}

	if err != nil || strings.TrimSpace(string(out)) == "" {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Details: details,
			Message: "XProtect metadata could not be read; the system may be running an older macOS version",
		}
	}

	details["xprotect_version"] = strings.TrimSpace(string(out))

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Details: details,
		Message: fmt.Sprintf("XProtect is present (version %s)", strings.TrimSpace(string(out))),
	}
}
