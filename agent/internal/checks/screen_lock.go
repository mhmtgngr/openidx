package checks

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ScreenLockCheck verifies that the device requires a password after the screen
// is locked or the screensaver activates.
//
// Linux: checks gsettings for the GNOME idle-delay and lock-enabled keys, or
// falls back to loginctl to see whether a session lock is configured.
//
// macOS: reads the com.apple.screensaver askForPassword default; a value of 1
// means the screen lock is active.
//
// All other operating systems receive a StatusWarn result.
type ScreenLockCheck struct{}

// Name implements Check.
func (c *ScreenLockCheck) Name() string { return "screen_lock" }

// Run implements Check.
func (c *ScreenLockCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkMacOS()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("screen lock check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

func (c *ScreenLockCheck) checkLinux() *CheckResult {
	details := map[string]interface{}{
		"os": "linux",
	}

	// Try GNOME gsettings first.
	lockEnabled, err := exec.Command("gsettings", "get",
		"org.gnome.desktop.screensaver", "lock-enabled").Output()
	if err == nil {
		enabled := strings.TrimSpace(string(lockEnabled)) == "true"
		details["method"] = "gsettings"
		if enabled {
			return &CheckResult{
				Status:  StatusPass,
				Score:   1.0,
				Details: details,
				Message: "screen lock is enabled (GNOME gsettings)",
			}
		}
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     "screen lock is disabled (GNOME gsettings lock-enabled = false)",
			Remediation: "Enable screen lock in GNOME Settings > Privacy > Screen Lock.",
		}
	}

	// Fall back to loginctl: check whether any session has a lock-screen.
	out, err := exec.Command("loginctl", "show-session", "self", "--property=LockedHint").Output()
	if err == nil {
		locked := strings.Contains(string(out), "LockedHint=yes")
		details["method"] = "loginctl"
		if locked {
			return &CheckResult{
				Status:  StatusPass,
				Score:   1.0,
				Details: details,
				Message: "screen lock is active (loginctl)",
			}
		}
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     "screen lock is not active (loginctl LockedHint=no)",
			Remediation: "Configure your desktop environment to require a password after inactivity.",
		}
	}

	return &CheckResult{
		Status:  StatusWarn,
		Score:   0.5,
		Details: details,
		Message: "could not determine screen lock status; gsettings and loginctl are unavailable",
	}
}

func (c *ScreenLockCheck) checkMacOS() *CheckResult {
	details := map[string]interface{}{
		"os":     "darwin",
		"method": "defaults",
	}

	out, err := exec.Command("defaults", "read",
		"com.apple.screensaver", "askForPassword").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Details: details,
			Message: "could not read com.apple.screensaver askForPassword preference",
		}
	}

	value := strings.TrimSpace(string(out))
	if value == "1" {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "screen lock password is required (askForPassword = 1)",
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     fmt.Sprintf("screen lock password is not required (askForPassword = %s)", value),
		Remediation: "Enable screen lock in System Settings > Lock Screen > Require password after screen saver begins.",
	}
}
