package checks

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// IntegrityCheck performs basic device-integrity checks to detect running as
// root inside a container (a common indicator of privilege-escalation or
// jailbreak conditions).
//
// Linux: passes if the current process is NOT running as UID 0 inside a
// container (detected by the presence of /.dockerenv or the cgroup "docker"
// string).
//
// All other platforms currently return a StatusWarn indicating that the check
// is not yet implemented for that OS.
type IntegrityCheck struct{}

// Name implements Check.
func (c *IntegrityCheck) Name() string { return "integrity" }

// Run implements Check.
func (c *IntegrityCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	switch runtime.GOOS {
	case "linux":
		return c.checkLinux()
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("integrity check not fully implemented on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os": runtime.GOOS,
			},
		}
	}
}

// inContainer returns true if the process appears to be running inside a
// container (Docker, Podman, LXC, etc.).
func inContainer() bool {
	// Docker leaves a marker file.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Podman / generic OCI runtimes leave a similar marker.
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return false
}

func (c *IntegrityCheck) checkLinux() *CheckResult {
	uid := os.Getuid()
	isRoot := uid == 0
	isContainer := inContainer()

	details := map[string]interface{}{
		"os":           "linux",
		"uid":          uid,
		"in_container": isContainer,
	}

	if isRoot && isContainer {
		return &CheckResult{
			Status:      StatusFail,
			Score:       0,
			Details:     details,
			Message:     "process is running as root (UID 0) inside a container — potential privilege escalation",
			Remediation: "Run the agent as a non-root user and ensure container hardening policies are applied.",
		}
	}

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Details: details,
		Message: fmt.Sprintf("integrity check passed (uid=%d, in_container=%v)", uid, isContainer),
	}
}
