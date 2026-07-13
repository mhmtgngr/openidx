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
	case "windows":
		return c.checkWindows()
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

// checkWindows inspects the machine screen-saver policy: a password-protected
// screensaver with a timeout is a reasonable "auto-lock" proxy. Reads the GPO
// policy hive first, then the per-user default.
func (c *ScreenLockCheck) checkWindows() *CheckResult {
	// ScreenSaverIsSecure=1 + ScreenSaveTimeOut>0 under the policy or control panel keys.
	const ps = `$p='HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop';` +
		`$u='HKCU:\Control Panel\Desktop';` +
		`function g($k,$n){ try { (Get-ItemProperty -Path $k -Name $n -ErrorAction Stop).$n } catch { $null } };` +
		`$sec=g $p 'ScreenSaverIsSecure'; if($sec -eq $null){$sec=g $u 'ScreenSaverIsSecure'};` +
		`$to=g $p 'ScreenSaveTimeOut'; if($to -eq $null){$to=g $u 'ScreenSaveTimeOut'};` +
		`"$sec|$to"`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("screen-lock policy query failed: %v", err),
			Details: map[string]interface{}{"os": "windows"},
		}
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	secure := len(parts) > 0 && strings.TrimSpace(parts[0]) == "1"
	timeout := ""
	if len(parts) > 1 {
		timeout = strings.TrimSpace(parts[1])
	}
	details := map[string]interface{}{"os": "windows", "secure": secure, "timeout_seconds": timeout, "method": "registry"}
	if secure && timeout != "" && timeout != "0" {
		return &CheckResult{Status: StatusPass, Score: 1.0, Details: details, Message: "password-protected auto-lock is configured"}
	}
	return &CheckResult{
		Status: StatusWarn, Score: 0.5, Details: details,
		Message:     "no password-protected screen-saver auto-lock detected",
		Remediation: "Enable a password-protected screen saver with a timeout, or apply a screen-lock GPO.",
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
