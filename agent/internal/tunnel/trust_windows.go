//go:build windows

package tunnel

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/openidx/openidx/agent/internal/plugin"
)

// verifyTrustedBinary refuses a tunneler the LocalSystem service must not
// run. The binary must sit under the machine's Program Files folder (resolved
// from the known-folder API, not from an environment variable), and the file
// and the two directories above it (the install folder and its parent) must
// pass the same owner and DACL check a plugin passes: only SYSTEM,
// Administrators and TrustedInstaller may change them. stopAt is unused on
// Windows; it exists for the Unix tests.
func verifyTrustedBinary(path, _ string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	inProgramFiles := false
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		root, kerr := windows.KnownFolderPath(id, 0)
		if kerr != nil || root == "" {
			continue
		}
		rel, rerr := filepath.Rel(root, real)
		if rerr == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			inProgramFiles = true
			break
		}
	}
	if !inProgramFiles {
		return fmt.Errorf("%w: %s is not under Program Files, where only administrators can "+
			"install software", ErrUntrustedBinary, real)
	}
	dir := filepath.Dir(real)
	for _, p := range []string{real, dir, filepath.Dir(dir)} {
		if err := plugin.CheckTrustedPath(p); err != nil {
			return fmt.Errorf("%w: %v", ErrUntrustedBinary, err)
		}
	}
	return nil
}
