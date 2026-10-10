//go:build !windows && !linux

package tunnel

// execPathFor executes the checked path. There is no /proc/self/fd to execute
// a descriptor through here, so a swap between the check and the exec is not
// closed on this platform; the ownership checks on every parent directory
// (verifyTrustedBinary) are what keep an ordinary account from making one. No
// tunneler is bundled for these platforms yet.
func execPathFor(h *heldBinary) (string, error) { return h.path, nil }
