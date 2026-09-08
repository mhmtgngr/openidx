package checks

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

// OSVersionCheck reports the current operating system name, version, and
// architecture.  An optional "min_version" param causes a version comparison
// and returns StatusFail when the running OS version is lower.
type OSVersionCheck struct{}

// Name implements Check.
func (c *OSVersionCheck) Name() string { return "os_version" }

// Run implements Check.
func (c *OSVersionCheck) Run(_ context.Context, params map[string]interface{}) *CheckResult {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	// getOSVersion is uname(2) on every non-Windows target. On Linux and macOS
	// that release string IS the OS version an administrator writes a
	// min_version policy against. On Android it is the LINUX KERNEL release —
	// "5.10.101" where the policy means "14" — and on iOS the same. Comparing
	// a kernel release against an Android version number does not produce a
	// wrong answer so much as a meaningless one, and min_version returns
	// StatusFail on a mismatch, so the meaningless comparison would have been
	// reported as a device failing policy.
	//
	// The Android agent reports this check from Build.VERSION, which is the
	// number the policy means. Refusing to answer here is what leaves one
	// answer per platform instead of two in different units; tools/posturevocab
	// fails the build if both clients ever claim it again.
	switch runtime.GOOS {
	case "android", "ios":
		return &CheckResult{
			Status:      StatusWarn,
			Score:       0.5,
			Unsupported: true,
			Message:     fmt.Sprintf("os version check not supported on %s (uname reports the kernel, not the OS release)", runtime.GOOS),
			Details: map[string]interface{}{
				"os":   osName,
				"arch": arch,
			},
		}
	}

	version := getOSVersion()

	details := map[string]interface{}{
		"os":      osName,
		"version": version,
		"arch":    arch,
	}

	minVersion, _ := params["min_version"].(string)
	if minVersion != "" {
		cmp := compareVersions(version, minVersion)
		if cmp < 0 {
			return &CheckResult{
				Status:      StatusFail,
				Score:       0,
				Details:     details,
				Message:     fmt.Sprintf("OS version %s is below minimum required %s", version, minVersion),
				Remediation: fmt.Sprintf("Upgrade the operating system to at least version %s.", minVersion),
			}
		}
	}

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Details: details,
		Message: fmt.Sprintf("OS: %s %s (%s)", osName, version, arch),
	}
}

// getOSVersion is implemented per-platform (os_version_unix.go / os_version_windows.go).

// compareVersions compares two dot-separated version strings.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func compareVersions(a, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// splitVersion parses a version string into numeric segments, stopping at the
// first non-numeric segment (e.g. "5.15.0-91-generic" → [5, 15, 0]).
func splitVersion(v string) []int {
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-'
	})
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		valid := len(p) > 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if !valid {
			break
		}
		nums = append(nums, n)
	}
	return nums
}
