package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Device fingerprints (Faz B8.4).
//
// The fingerprint names the machine, not its name: it is a hash of the OS
// machine id alone (Windows MachineGuid, Linux machine-id, macOS
// IOPlatformUUID), so renaming a PC keeps it one agent on the server. The
// hostname is sent as an attribute of its own.
//
// Agents before this one folded the hostname into the hash. For at least three
// releases the agent also sends that old value as device_fingerprint_prev, so
// the server finds the row enrolled under it and moves it to the stable one.
//
// A machine whose id cannot be read has nothing stable to offer; it sends the
// old hostname-folded value as its fingerprint, as before.

// stableFingerprint is the v2 fingerprint: prefix + a hash of the machine id
// alone, or "" when there is no machine id.
func stableFingerprint(prefix, machineID string) string {
	id := strings.ToLower(strings.TrimSpace(machineID))
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return prefix + hex.EncodeToString(sum[:16])
}

// legacyFingerprint is the fingerprint agents before v2 sent: the machine id
// and the hostname, hashed together.
func legacyFingerprint(prefix, machineID, hostname string) string {
	seed := strings.ToLower(strings.TrimSpace(machineID)) + "|" + strings.ToLower(strings.TrimSpace(hostname))
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:16])
}

// fingerprints returns what an enrolment sends: the fingerprint and, when it
// differs, the one an older agent sent for this machine.
func fingerprints(stablePrefix, legacyPrefix, machineID, legacyID, hostname string) (fp, prev string) {
	legacy := legacyFingerprint(legacyPrefix, legacyID, hostname)
	fp = stableFingerprint(stablePrefix, machineID)
	if fp == "" {
		return legacy, ""
	}
	return fp, legacy
}

// deviceFingerprints is fingerprints for this machine.
func deviceFingerprints(hostname string) (fp, prev string) {
	id := machineID()
	return fingerprints(stableFingerprintPrefix, legacyFingerprintPrefix, id, legacyMachineID(id), hostname)
}
