//go:build linux

package tunnel

import (
	"fmt"
	"os"
)

// execPathFor executes the held descriptor itself. The kernel resolves
// /proc/self/fd/N to the open file in the child before close-on-exec runs, so
// the inode that was checked is the one that runs, even if the path has been
// swapped since.
func execPathFor(h *heldBinary) (string, error) {
	p := fmt.Sprintf("/proc/self/fd/%d", h.file.Fd())
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%w: /proc is not available to execute the checked file: %v",
			ErrUntrustedBinary, err)
	}
	return p, nil
}
