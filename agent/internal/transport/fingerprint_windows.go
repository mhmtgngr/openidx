//go:build windows

package transport

import "golang.org/x/sys/windows/registry"

const (
	stableFingerprintPrefix = "win2:"
	legacyFingerprintPrefix = "win:"
)

// machineID is HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, stable across
// reinstalls of the agent and renames of the PC. Only its hash is sent.
func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return v
}

// legacyMachineID is the machine id older agents folded into their fingerprint.
func legacyMachineID(id string) string { return id }
