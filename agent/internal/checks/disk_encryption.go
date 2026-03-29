package checks

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// DiskEncryptionCheck verifies that full-disk encryption is enabled on the
// current device.
//
// Linux: runs `lsblk -o TYPE` and looks for a "crypt" device type, which
// indicates that dm-crypt/LUKS is active.
//
// macOS: runs `fdesetup status` and checks whether the output contains
// "FileVault is On".
//
// All other operating systems receive a StatusWarn result because the check
// cannot determine encryption status.
type DiskEncryptionCheck struct{}

// Name implements Check.
func (c *DiskEncryptionCheck) Name() string { return "disk_encryption" }

// Run implements Check.
func (c *DiskEncryptionCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	case "darwin":
		return c.checkMacOS()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("disk encryption check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

// checkLinux uses lsblk to detect LUKS/dm-crypt encrypted devices.
func (c *DiskEncryptionCheck) checkLinux() *CheckResult {
	out, err := exec.Command("lsblk", "-o", "TYPE").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("lsblk failed: %v", err),
			Details: map[string]interface{}{"os": "linux"},
		}
	}

	encrypted := strings.Contains(string(out), "crypt")
	details := map[string]interface{}{
		"os":        "linux",
		"encrypted": encrypted,
		"method":    "lsblk",
	}

	if encrypted {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "disk encryption (LUKS/dm-crypt) is active",
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "no encrypted block device found; disk encryption does not appear to be active",
		Remediation: "Enable full-disk encryption using LUKS (e.g. `cryptsetup luksFormat`) or an equivalent tool.",
	}
}

// checkMacOS uses fdesetup to determine whether FileVault is enabled.
func (c *DiskEncryptionCheck) checkMacOS() *CheckResult {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("fdesetup failed: %v", err),
			Details: map[string]interface{}{"os": "darwin"},
		}
	}

	encrypted := strings.Contains(string(out), "FileVault is On")
	details := map[string]interface{}{
		"os":        "darwin",
		"encrypted": encrypted,
		"method":    "fdesetup",
	}

	if encrypted {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: "FileVault is enabled",
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     "FileVault is not enabled",
		Remediation: "Enable FileVault in System Settings > Privacy & Security > FileVault.",
	}
}
