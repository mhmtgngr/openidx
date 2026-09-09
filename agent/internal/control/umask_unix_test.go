//go:build !windows

package control

import (
	"syscall"
	"testing"
)

// umaskForTest sets the process umask and returns the previous value.
//
// In its own file because syscall.Umask is process-global: a test that changes
// it changes it for every other test running in the same binary. Go runs the
// tests in one package sequentially unless t.Parallel() is called, and none in
// this package is parallel — stated here rather than assumed, because the day
// one becomes parallel this helper is where the flake comes from.
func umaskForTest(t *testing.T, mask int) int {
	t.Helper()
	return syscall.Umask(mask)
}
