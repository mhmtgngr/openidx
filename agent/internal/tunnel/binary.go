package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PinnedBinarySHA256, when set at build time
// (-X github.com/openidx/openidx/agent/internal/tunnel.PinnedBinarySHA256=<hex>),
// is the SHA-256 of the one tunneler binary this agent build will run. The
// release workflow sets it from the binary it verified and bundled. The held
// file is hashed when it is opened and again before every start; a mismatch is
// refused. Empty (a development build) skips the comparison and leaves the
// ownership and permission checks.
var PinnedBinarySHA256 = ""

// ErrBinaryMismatch is returned when the tunneler does not match
// PinnedBinarySHA256.
var ErrBinaryMismatch = errors.New("the tunneler binary does not match the build's pinned SHA-256")

// heldBinary is a tunneler binary the supervisor has opened, checked through
// the open handle, and keeps open for as long as it runs it. Checking a path
// and executing the path later leaves a window in which the file can be
// swapped; holding it closes that window per platform:
//
//   - Linux: the file is opened with O_NOFOLLOW, its owner and mode are read
//     from the open descriptor, and it is executed THROUGH that descriptor
//     (/proc/self/fd/N), so what runs is the inode that was checked, whatever
//     the path names by then.
//   - Windows: the file (and wintun.dll beside it) is opened without
//     FILE_SHARE_WRITE or FILE_SHARE_DELETE, so for as long as the handle is
//     held nobody can write, delete or rename it; the handle's final path is
//     compared with the checked path, and reparse points are refused.
//   - Elsewhere (macOS: no tunneler is bundled yet), the path is executed after
//     the checks, and the window remains; see binary_other.go.
type heldBinary struct {
	path     string   // the checked path
	execPath string   // what is executed: the path, or /proc/self/fd/N
	file     *os.File // the held binary, for hashing
	extra    []*os.File
	sum      string // SHA-256 when opened
	dev, ino uint64 // Unix identity, to notice a replaced file
}

// command builds the exec.Cmd that runs the held binary. argv[0] is the
// binary's name, whatever path it is executed through.
func (h *heldBinary) command(ctx context.Context, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if ctx != nil {
		cmd = exec.CommandContext(ctx, h.execPath, args...)
	} else {
		cmd = exec.Command(h.execPath, args...)
	}
	cmd.Args[0] = filepath.Base(h.path)
	return cmd
}

// hash reads the held file from the start, through the handle.
func (h *heldBinary) hash() (string, error) {
	fi, err := h.file.Stat()
	if err != nil {
		return "", err
	}
	d := sha256.New()
	if _, err := io.Copy(d, io.NewSectionReader(h.file, 0, fi.Size())); err != nil {
		return "", err
	}
	return hex.EncodeToString(d.Sum(nil)), nil
}

// verifyPin hashes the held file again and compares it with the build's pin
// and with the hash taken when it was opened.
func (h *heldBinary) verifyPin() error {
	sum, err := h.hash()
	if err != nil {
		return fmt.Errorf("hashing the tunneler: %w", err)
	}
	if sum != h.sum {
		return fmt.Errorf("%w: it changed since it was checked", ErrBinaryMismatch)
	}
	return checkPin(sum)
}

func checkPin(sum string) error {
	if pin := strings.ToLower(strings.TrimSpace(PinnedBinarySHA256)); pin != "" && sum != pin {
		return fmt.Errorf("%w: got %s, pinned %s", ErrBinaryMismatch, sum, pin)
	}
	return nil
}

func (h *heldBinary) close() {
	if h == nil {
		return
	}
	if h.file != nil {
		_ = h.file.Close()
	}
	for _, f := range h.extra {
		_ = f.Close()
	}
}

// finishOpen hashes a freshly opened binary and applies the pin.
func finishOpen(h *heldBinary) (*heldBinary, error) {
	sum, err := h.hash()
	if err != nil {
		h.close()
		return nil, fmt.Errorf("hashing the tunneler: %w", err)
	}
	if err := checkPin(sum); err != nil {
		h.close()
		return nil, err
	}
	h.sum = sum
	return h, nil
}

// errNotRegular is returned for a path that is a link, directory or device.
var errNotRegular = errors.New("is not a regular file")

// statOK checks what any platform can check through the handle.
func statOK(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errNotRegular
	}
	return nil
}
