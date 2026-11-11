package updater

import (
	"io"
	"os"
	"path/filepath"
)

// keepPrevious rotates the installer kept from the last update to prev.<ext>
// and keeps a copy of path as current.<ext>, both in the private update
// directory, so an administrator (or a later rollback command) has the build
// the device ran before this one. Best-effort: a failure here never stops
// the update.
func keepPrevious(dir, path string) {
	ext := filepath.Ext(path)
	cur := filepath.Join(dir, "current"+ext)
	prev := filepath.Join(dir, "prev"+ext)
	if _, err := os.Stat(cur); err == nil {
		_ = os.Remove(prev)
		_ = os.Rename(cur, prev)
	}
	in, err := os.Open(path) //nolint:gosec // path is the verified artifact in the private update directory
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.OpenFile(cur, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // fixed name in the private directory
	if err != nil {
		return
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(cur)
		return
	}
	_ = out.Close()
}
