//go:build !windows

package checks

import (
	"strings"

	"golang.org/x/sys/unix"
)

// getOSVersion retrieves the kernel/OS release string via uname on Linux/macOS.
func getOSVersion() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown"
	}
	// Release is a fixed-size byte array; convert to a Go string stopping at the
	// first NUL byte.
	b := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	if len(b) == 0 {
		return "unknown"
	}
	return strings.SplitN(string(b), "-", 2)[0]
}
