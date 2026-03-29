package checks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const defaultMaxDays = 30

// PatchLevelCheck verifies that the operating system has been updated recently.
//
// Linux: checks the modification time of
// /var/lib/apt/periodic/update-success-stamp (Debian/Ubuntu). If that file is
// absent, falls back to parsing `rpm -qa --last` (RHEL/Fedora).
//
// macOS: parses `softwareupdate --history` and uses the date of the most recent
// entry.
//
// params["max_days"]: maximum number of days since the last update before the
// check fails (default 30).
type PatchLevelCheck struct{}

// Name implements Check.
func (c *PatchLevelCheck) Name() string { return "patch_level" }

// Run implements Check.
func (c *PatchLevelCheck) Run(_ context.Context, params map[string]interface{}) *CheckResult {
	maxDays := defaultMaxDays
	if v, ok := params["max_days"]; ok {
		switch n := v.(type) {
		case int:
			maxDays = n
		case float64:
			maxDays = int(n)
		case int64:
			maxDays = int(n)
		}
	}

	switch runtime.GOOS {
	case "linux":
		return c.checkLinux(maxDays)
	case "darwin":
		return c.checkMacOS(maxDays)
	default:
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("patch level check not supported on %s", runtime.GOOS),
			Details: map[string]interface{}{
				"os":       runtime.GOOS,
				"max_days": maxDays,
			},
		}
	}
}

func (c *PatchLevelCheck) resultFromAge(daysSince, maxDays int, method, os string) *CheckResult {
	details := map[string]interface{}{
		"os":                os,
		"method":            method,
		"days_since_update": daysSince,
		"max_days":          maxDays,
	}

	if daysSince <= maxDays {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Details: details,
			Message: fmt.Sprintf("last update was %d day(s) ago (limit: %d days)", daysSince, maxDays),
		}
	}

	return &CheckResult{
		Status:      StatusFail,
		Score:       0,
		Details:     details,
		Message:     fmt.Sprintf("last update was %d day(s) ago, exceeding the %d-day limit", daysSince, maxDays),
		Remediation: "Run system updates to bring the device up to date.",
	}
}

func (c *PatchLevelCheck) checkLinux(maxDays int) *CheckResult {
	// Debian/Ubuntu: apt stamp file.
	const aptStamp = "/var/lib/apt/periodic/update-success-stamp"
	if info, err := os.Stat(aptStamp); err == nil {
		days := int(time.Since(info.ModTime()).Hours() / 24)
		return c.resultFromAge(days, maxDays, "apt-stamp", "linux")
	}

	// RHEL/Fedora: rpm -qa --last, most recent line first.
	out, err := exec.Command("rpm", "-qa", "--last").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "could not determine last update time (apt stamp absent, rpm unavailable)",
			Details: map[string]interface{}{
				"os":       "linux",
				"max_days": maxDays,
			},
		}
	}

	// rpm --last output format: "<name>  <Day Mon DD HH:MM:SS YYYY>"
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "rpm -qa --last returned no results",
			Details: map[string]interface{}{
				"os":       "linux",
				"max_days": maxDays,
			},
		}
	}

	// The first line is the most recently installed package.
	fields := strings.Fields(lines[0])
	// Fields: [pkg-name, Day, Mon, DD, HH:MM:SS, YYYY]
	if len(fields) >= 6 {
		dateStr := strings.Join(fields[len(fields)-5:], " ")
		if t, err := time.Parse("Mon Jan 2 15:04:05 2006", dateStr); err == nil {
			days := int(time.Since(t).Hours() / 24)
			return c.resultFromAge(days, maxDays, "rpm", "linux")
		}
	}

	return &CheckResult{
		Status:  StatusWarn,
		Score:   0.5,
		Message: "could not parse rpm --last output to determine update age",
		Details: map[string]interface{}{
			"os":       "linux",
			"max_days": maxDays,
		},
	}
}

func (c *PatchLevelCheck) checkMacOS(maxDays int) *CheckResult {
	out, err := exec.Command("softwareupdate", "--history").Output()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: fmt.Sprintf("softwareupdate --history failed: %v", err),
			Details: map[string]interface{}{
				"os":       "darwin",
				"max_days": maxDays,
			},
		}
	}

	// softwareupdate --history output (macOS 12+) has lines like:
	//   <Name>   <Version>   <Date>   <Time>
	// Date format: MM/DD/YYYY or YYYY-MM-DD depending on locale/version.
	var mostRecent time.Time
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Try the last two fields as "date time".
		dateStr := fields[len(fields)-2] + " " + fields[len(fields)-1]
		// Try common formats.
		for _, layout := range []string{
			"01/02/2006 15:04:05",
			"2006-01-02 15:04:05",
			"01/02/2006 3:04 PM",
		} {
			if t, err := time.Parse(layout, dateStr); err == nil {
				if t.After(mostRecent) {
					mostRecent = t
				}
				break
			}
		}
	}

	if mostRecent.IsZero() {
		return &CheckResult{
			Status:  StatusWarn,
			Score:   0.5,
			Message: "no software update history found or date could not be parsed",
			Details: map[string]interface{}{
				"os":       "darwin",
				"max_days": maxDays,
			},
		}
	}

	days := int(time.Since(mostRecent).Hours() / 24)
	return c.resultFromAge(days, maxDays, "softwareupdate", "darwin")
}
