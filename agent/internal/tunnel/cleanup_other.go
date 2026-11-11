//go:build !windows

package tunnel

// Cleanup is a no-op off Windows: a stopped tunneler there exits cleanly and
// removes its own routes and resolver entries.
func Cleanup() error { return nil }
