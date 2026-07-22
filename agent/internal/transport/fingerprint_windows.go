//go:build windows

package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// deviceFingerprint returns a stable per-machine identifier so re-enrollment of
// the same Windows device reuses one agent identity. It prefers the OS
// MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid), which is
// stable across reinstalls of our agent, and folds in the hostname. Falls back
// to the hostname alone if the registry value is unavailable. The value is
// hashed so we never ship the raw MachineGuid to the server.
func deviceFingerprint(hostname string) string {
	guid := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if v, _, gerr := k.GetStringValue("MachineGuid"); gerr == nil {
			guid = v
		}
		k.Close()
	}
	seed := strings.ToLower(strings.TrimSpace(guid)) + "|" + strings.ToLower(strings.TrimSpace(hostname))
	sum := sha256.Sum256([]byte(seed))
	return "win:" + hex.EncodeToString(sum[:16])
}
