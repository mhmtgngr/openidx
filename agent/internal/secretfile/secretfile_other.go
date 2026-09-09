//go:build !windows

package secretfile

import (
	"fmt"
	"os"
)

// protect is a no-op off Windows: the 0600 mode Write applies is the control
// the platform enforces, and encrypting at rest with a key the same process
// can fetch unaided adds ceremony rather than protection.
func protect(data []byte) (blob []byte, protected bool, err error) {
	return data, false, nil
}

// unprotect is only reached for a file carrying the marker, which off Windows
// means it was written on Windows and copied here — DPAPI is per-user and
// per-machine, so the bytes cannot be recovered. Say that, rather than return
// something unusable.
func unprotect(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("this secret was encrypted with Windows DPAPI and cannot be read on this platform; sign in again to write a fresh one")
}

// harden re-asserts 0600 on the file. os.WriteFile applies the mode only when
// it CREATES the file: rewriting an existing one keeps whatever mode it had,
// so a token file that was once world-readable would stay world-readable.
func harden(path string) error {
	return os.Chmod(path, 0o600)
}
