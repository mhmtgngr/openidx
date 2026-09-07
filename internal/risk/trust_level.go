package risk

// TrustLevel is how far a device has earned its way past a first sighting.
//
// It is what survives of device.go, which held a DeviceFingerprinter: canvas,
// WebGL and optional audio fingerprint capture, a fingerprint store, trust
// levels computed from a seen-count, and a suspicious-change detector. Nothing
// constructed it, and its configuration comments describe browser-side
// collection that no page in web/admin-console performs -- the live device
// signal is the posture agent and device_trust, which is a different mechanism
// with a different threat model.
//
// These four values are used by the risk scorer's device-trust signal and by
// the service's login-context evaluation, so they stay.
type TrustLevel string

const (
	TrustLevelTrusted    TrustLevel = "trusted"    // Seen 5+ times, explicitly trusted
	TrustLevelKnown      TrustLevel = "known"      // Seen before, but not yet 5 times
	TrustLevelUnknown    TrustLevel = "unknown"    // First time seen
	TrustLevelSuspicious TrustLevel = "suspicious" // Fingerprint changed for known device
)
