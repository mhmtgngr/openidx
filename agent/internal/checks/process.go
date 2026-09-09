package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ProcessCheck verifies that a list of expected processes is currently running.
// The required process names are supplied via params["processes"] as a
// []interface{} of strings.  The check returns StatusPass when all processes
// are found, StatusFail when any are missing, and StatusPass (score=1) when
// no processes are configured.
type ProcessCheck struct{}

// Name implements Check.
func (c *ProcessCheck) Name() string { return "process_running" }

// Run implements Check.
func (c *ProcessCheck) Run(_ context.Context, params map[string]interface{}) *CheckResult {
	required := parseProcessList(params)
	if len(required) == 0 {
		return &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Message: "no processes configured to check",
		}
	}

	// The enumeration below globs /proc, which is the process table on Linux
	// and on nothing else this agent runs on. On Windows and macOS the glob
	// matches nothing; on Android the kernel has hidden other processes from
	// unprivileged apps since API 24; on iOS there is no /proc at all. In every
	// one of those cases listRunningProcesses returns an EMPTY list without an
	// error, so every configured process was reported missing and the check
	// returned StatusFail — naming processes that were very likely running.
	//
	// A check that cannot see the process table must say so. Reporting a
	// failure it cannot substantiate is worse than reporting nothing: it puts
	// a red mark on a healthy machine, and an operator who learns to ignore it
	// has learned to ignore the real ones too.
	if runtime.GOOS != "linux" {
		return &CheckResult{
			Status:      StatusWarn,
			Score:       0.5,
			Unsupported: true,
			Message:     fmt.Sprintf("process check not supported on %s (no readable process table)", runtime.GOOS),
			Details: map[string]interface{}{
				"os":       runtime.GOOS,
				"required": required,
			},
		}
	}

	running, err := listRunningProcesses()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Score:   0,
			Message: fmt.Sprintf("failed to list running processes: %v", err),
		}
	}

	missing := make([]string, 0)
	for _, name := range required {
		if !isRunning(running, name) {
			missing = append(missing, name)
		}
	}

	found := len(required) - len(missing)
	score := float64(found) / float64(len(required))

	details := map[string]interface{}{
		"required": required,
		"missing":  missing,
		"found":    found,
		"total":    len(required),
	}

	if len(missing) > 0 {
		return &CheckResult{
			Status:      StatusFail,
			Score:       score,
			Details:     details,
			Message:     fmt.Sprintf("%d of %d required processes not running: %s", len(missing), len(required), strings.Join(missing, ", ")),
			Remediation: "Ensure the required processes are installed and running.",
		}
	}

	return &CheckResult{
		Status:  StatusPass,
		Score:   1.0,
		Details: details,
		Message: fmt.Sprintf("all %d required processes are running", len(required)),
	}
}

// parseProcessList extracts process names from params["processes"].
func parseProcessList(params map[string]interface{}) []string {
	raw, ok := params["processes"]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	names := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			names = append(names, s)
		}
	}
	return names
}

// listRunningProcesses reads /proc/*/cmdline on Linux to enumerate running
// processes.  On non-Linux platforms it returns an empty list without error.
func listRunningProcesses() ([]string, error) {
	matches, err := filepath.Glob("/proc/*/cmdline")
	if err != nil {
		return nil, fmt.Errorf("globbing /proc: %w", err)
	}
	if matches == nil {
		// Non-Linux platform or empty /proc — return empty list gracefully.
		return []string{}, nil
	}

	procs := make([]string, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			// Process may have exited; skip silently.
			continue
		}
		if len(data) == 0 {
			continue
		}
		// cmdline fields are NUL-separated; the first field is the executable.
		exe := strings.SplitN(string(data), "\x00", 2)[0]
		if exe != "" {
			procs = append(procs, exe)
		}
	}
	return procs, nil
}

// isRunning returns true if any running process cmdline contains name.
// The comparison uses a substring match against the base name of each
// running process executable.
func isRunning(procs []string, name string) bool {
	for _, p := range procs {
		base := filepath.Base(p)
		if base == name || strings.Contains(p, name) {
			return true
		}
	}
	return false
}
