//go:build !windows

package tunnel

import (
	"fmt"
	"os"
	"syscall"
)

// openBinary opens path without following a final symlink, checks the OPEN
// file's owner and mode (the same rule verifyTrustedBinary applies to the
// path), and holds it. On Linux it is then executed through its descriptor
// (binary_linux.go); elsewhere through its path (binary_other.go).
func openBinary(path string) (*heldBinary, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %v", ErrUntrustedBinary, path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	h := &heldBinary{path: path, file: f}
	fi, err := f.Stat()
	if err != nil {
		h.close()
		return nil, fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	if err := statOK(fi); err != nil {
		h.close()
		return nil, fmt.Errorf("%w: %s %v", ErrUntrustedBinary, path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		h.close()
		return nil, fmt.Errorf("%w: cannot read the owner of %s", ErrUntrustedBinary, path)
	}
	if uid := uint32(st.Uid); uid != 0 && uid != uint32(os.Geteuid()) {
		h.close()
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not root", ErrUntrustedBinary, path, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 || perm&0o111 == 0 {
		h.close()
		return nil, fmt.Errorf("%w: %s is mode %04o (must be executable and not group/world-writable)",
			ErrUntrustedBinary, path, perm)
	}
	h.dev, h.ino = uint64(st.Dev), uint64(st.Ino)
	if h.execPath, err = execPathFor(h); err != nil {
		h.close()
		return nil, err
	}
	return finishOpen(h)
}

// stillCurrent reports whether path still names the held file. A package
// upgrade replaces it; the supervisor then opens and checks the new one.
func (h *heldBinary) stillCurrent() bool {
	var st syscall.Stat_t
	if err := syscall.Stat(h.path, &st); err != nil {
		return false
	}
	return uint64(st.Dev) == h.dev && uint64(st.Ino) == h.ino
}
