//go:build darwin

package transport

import (
	"os/exec"
	"regexp"
)

const (
	stableFingerprintPrefix = "mac2:"
	legacyFingerprintPrefix = "nix:"
)

var ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// machineID is the IOPlatformUUID of the Mac. Only its hash is sent.
func machineID() string {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	if m := ioPlatformUUID.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// legacyMachineID is the machine id older agents folded into their
// fingerprint: they read /etc/machine-id, which a Mac does not have.
func legacyMachineID(string) string { return "" }
