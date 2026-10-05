//go:build !windows

package updater

import "os"

// makePrivate makes dir writable by its owner alone. The mode bits are the
// control here; plugin.CheckTrustedPath then confirms them.
func makePrivate(dir string) error { return os.Chmod(dir, 0o700) }
