//go:build windows

package tunnel

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/openidx/openidx/agent/internal/plugin"
)

// verifyTrustedBinary refuses a file the LocalSystem service must not run or
// let the tunneler load. The file must sit under the machine's native Program
// Files folder, and the file and EVERY folder from it up to and including
// Program Files itself must pass the owner and DACL check a plugin passes
// (plugin.CheckTrustedPath):
//
//   - the owner must be SYSTEM, Administrators or TrustedInstaller (or this
//     process's own account, which is SYSTEM in the service);
//   - no allow entry may grant write, append, delete, delete-child, WRITE_DAC
//     or WRITE_OWNER (generic bits included) to anyone else;
//   - deny entries only narrow access and are not counted as grants;
//     inherit-only entries do not apply to the object and are skipped; a
//     conditional/object/callback entry, which this check cannot evaluate, and
//     a NULL DACL are refusals.
//
// The walk stops at Program Files because the volume root above it
// deliberately lets Authenticated Users create folders, and Program Files
// itself cannot be renamed by them. Program Files is resolved with the
// known-folder API, not an environment variable, and only FOLDERID_ProgramFiles
// is accepted: for the 64-bit agent that is the native folder, and the
// 32-bit "Program Files (x86)" is not where the MSI installs it. stopAt is
// unused on Windows; it exists for the Unix tests.
func verifyTrustedBinary(path, _ string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || root == "" {
		return fmt.Errorf("%w: cannot locate Program Files: %v", ErrUntrustedBinary, err)
	}
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: %s is not under %s, where only administrators can install software",
			ErrUntrustedBinary, real, root)
	}
	for p := real; ; p = filepath.Dir(p) {
		if err := plugin.CheckTrustedPath(p); err != nil {
			return fmt.Errorf("%w: %v", ErrUntrustedBinary, err)
		}
		if strings.EqualFold(p, root) || filepath.Dir(p) == p {
			return nil
		}
	}
}
