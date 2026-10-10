//go:build !windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// verifyTrustedBinary refuses a tunneler that an account other than root (or
// the account this process runs as, which already controls it) could replace:
// the file and EVERY directory above it, up to stopAt ("" = the filesystem
// root), must be owned by root or by this process's user and must not be
// writable by group or other. All the ancestors count, unlike the plugin
// check, because whoever can write any directory on the way can rename the
// one below it and put their own tree in its place. Symlinks are resolved
// first, so it is the real file and its real parents that are checked.
//
// In production the agent runs as root when it starts the tunneler (child
// mode), so "this process's user" is root and the rule is root-only.
func verifyTrustedBinary(path, stopAt string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	if stopAt != "" {
		if stopAt, err = filepath.EvalSymlinks(stopAt); err != nil {
			return fmt.Errorf("%w: %v", ErrUntrustedBinary, err)
		}
	}
	euid := uint32(os.Geteuid())
	check := func(p string) error {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, p, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%w: cannot read the owner of %s", ErrUntrustedBinary, p)
		}
		if st.Uid != 0 && st.Uid != euid {
			return fmt.Errorf("%w: %s is owned by uid %d, not root; this process would run "+
				"whatever that account puts there", ErrUntrustedBinary, p, st.Uid)
		}
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%w: %s is mode %04o, writable by group or others (chmod go-w)",
				ErrUntrustedBinary, p, perm)
		}
		return nil
	}
	if err := check(real); err != nil {
		return err
	}
	for dir := filepath.Dir(real); ; {
		if err := check(dir); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if dir == stopAt || parent == dir {
			return nil
		}
		dir = parent
	}
}
