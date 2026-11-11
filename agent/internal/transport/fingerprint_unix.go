//go:build !windows && !darwin

package transport

import (
	"os"
	"strings"
)

const (
	stableFingerprintPrefix = "nix2:"
	legacyFingerprintPrefix = "nix:"
)

// machineID is the systemd/dbus machine-id. Only its hash is sent.
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// legacyMachineID is the machine id older agents folded into their fingerprint.
func legacyMachineID(id string) string { return id }
