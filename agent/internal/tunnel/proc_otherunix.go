//go:build !windows && !linux

package tunnel

import "os/exec"

// configureChild has nothing to set on this platform.
func configureChild(*exec.Cmd) {}
