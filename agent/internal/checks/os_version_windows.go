//go:build windows

package checks

import (
	"os/exec"
	"strings"
)

// getOSVersion parses the Windows version from `cmd /c ver`, e.g.
// "Microsoft Windows [Version 10.0.19045.3803]" → "10.0.19045.3803".
func getOSVersion() string {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return "unknown"
	}
	s := string(out)
	i := strings.Index(s, "Version ")
	if i < 0 {
		return "unknown"
	}
	rest := s[i+len("Version "):]
	if j := strings.IndexAny(rest, "]\r\n"); j >= 0 {
		rest = rest[:j]
	}
	v := strings.TrimSpace(rest)
	if v == "" {
		return "unknown"
	}
	return v
}
