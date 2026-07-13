//go:build !windows

package updater

import "errors"

// apply is unsupported off Windows (MSI self-update is Windows-only).
func apply(_ string) error {
	return errors.New("MSI self-update is only supported on Windows")
}
