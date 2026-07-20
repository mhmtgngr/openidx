//go:build !windows

package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// deviceFingerprint returns a stable per-machine identifier on non-Windows
// platforms. It prefers a persistent machine-id (systemd/dbus) and folds in the
// hostname, hashing the result. Falls back to the hostname alone. This keeps
// re-enrollment idempotent on Linux/macOS too, without shipping the raw id.
func deviceFingerprint(hostname string) string {
	id := ""
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			id = strings.TrimSpace(string(b))
			if id != "" {
				break
			}
		}
	}
	seed := strings.ToLower(id) + "|" + strings.ToLower(strings.TrimSpace(hostname))
	sum := sha256.Sum256([]byte(seed))
	prefix := "nix:"
	return prefix + hex.EncodeToString(sum[:16])
}
