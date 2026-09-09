//go:build !windows

package plugin

import (
	"fmt"
	"os"
)

// checkTrustedPath refuses a path that is writable by group or other.
//
// Mode bits are the control here, so this is the whole check. Ownership is
// deliberately NOT compared against the running uid: the daemon runs as root on
// a managed host and the plugins are laid down by a package or a config
// management tool as root, so requiring same-owner would refuse the normal
// arrangement while adding nothing — a file only root can write is already only
// replaceable by root.
func checkTrustedPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("%s is mode %04o: writable by %s, and this process executes what it "+
			"finds there. Make it 0755 or tighter (chmod go-w)", path, mode, writers(mode))
	}
	return nil
}

// writers names which of group/other can write, so the message says what to fix
// rather than leaving the reader to decode an octal mode.
func writers(mode os.FileMode) string {
	switch {
	case mode&0o020 != 0 && mode&0o002 != 0:
		return "the group and everyone"
	case mode&0o020 != 0:
		return "the group"
	default:
		return "everyone"
	}
}
