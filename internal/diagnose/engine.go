package diagnose

import (
	"sort"
	"time"
)

// Device statuses, as the fleet records them.
const (
	DeviceActive    = "active"
	DevicePending   = "pending"
	DeviceSuspended = "suspended"
	DeviceRevoked   = "revoked"
)

// StaleBundle is how old a bundle may be and still describe the present.
const StaleBundle = 15 * time.Minute

// Evidence is everything known about one failure to connect. Every part is
// optional: a nil part means "not known", which is never read as "fine".
type Evidence struct {
	// Now is when the evidence was gathered.
	Now time.Time
	// Bundle is the device doctor's report, when the device sent one.
	Bundle *Bundle
	// Device is the server's record of the device; nil when the person has
	// no device at all.
	Device *DeviceFacts
	// Access is the decision for the resource the person asked about.
	Access *AccessFacts
	// Service is the overlay's view of that resource.
	Service *ServiceFacts
}

// DeviceFacts is the server's record of a device.
type DeviceFacts struct {
	Status string
	// Live says the device reported within the liveness window.
	Live bool
	// Compliant is nil when posture has never been reported.
	Compliant *bool
	// Outdated says the device runs an agent older than its update target.
	Outdated bool
	// TunnelState is the last tunnel state the device reported, or "".
	TunnelState string
}

// AccessFacts is the access decision for one resource.
type AccessFacts struct {
	Assigned       bool
	StepUpRequired bool
	// DeviceTrustRequired says the resource needs a trusted device, which a
	// non-compliant one is not.
	DeviceTrustRequired bool
}

// ServiceFacts is the overlay's view of one service.
type ServiceFacts struct {
	Exists        bool
	HasTerminator bool
	// DialAllowed says a dial policy covers this device's identity.
	DialAllowed bool
}

// Cause is one reason, with what addresses it.
type Cause struct {
	Code string `json:"code"`
	// Source is "device" when the device's own report says so, "server" when
	// the server's records do.
	Source string `json:"source"`
	Fixes  []Fix  `json:"fixes"`
}

// Verdict is the diagnosis: causes in order of how much each explains. The
// first is the one to show; the rest are worth listing.
type Verdict struct {
	Healthy bool    `json:"healthy"`
	Causes  []Cause `json:"causes"`
	// BundleStale says the device's report was too old to be used.
	BundleStale bool `json:"bundle_stale,omitempty"`
}

// Primary is the leading cause code, or "" when healthy.
func (v Verdict) Primary() string {
	if len(v.Causes) == 0 {
		return ""
	}
	return v.Causes[0].Code
}

// bundleCauses maps the device doctor's codes onto causes.
var bundleCauses = map[string]string{
	"NOT_ENROLLED":         CauseNotEnrolled,
	"AUTH_INVALID":         CauseAuthInvalid,
	"DEVICE_REVOKED":       CauseDeviceRevoked,
	"DNS_FAIL":             CauseDNSFail,
	"DNS_TIMEOUT":          CauseDNSFail,
	"TCP_BLOCKED":          CauseNetworkBlocked,
	"TCP_TIMEOUT":          CauseNetworkBlocked,
	"HTTP_FAIL":            CauseNetworkBlocked,
	"HTTP_TIMEOUT":         CauseNetworkBlocked,
	"TLS_UNTRUSTED":        CauseTLSIntercepted,
	"TLS_FAIL":             CauseNetworkBlocked,
	"PROXY_AUTH_REQUIRED":  CauseProxyBlock,
	"SERVER_HTTP_ERROR":    CauseServerError,
	"CLOCK_SKEW":           CauseClockSkew,
	"IDENTITY_MISSING":     CauseIdentityExpired,
	"IDENTITY_EXPIRED":     CauseIdentityExpired,
	"IDENTITY_INVALID":     CauseIdentityExpired,
	"SERVICE_NOT_RUNNING":  CauseServiceNotRunning,
	"TUNNEL_DOWN":          CauseTunnelDown,
	"TUNNEL_NOT_INSTALLED": CauseTunnelNotInstalled,
}

// Evaluate is the rule engine. It never fails and never guesses: with no
// evidence that explains a failure it says UNKNOWN, and it says Healthy only
// when every part of the evidence that is present is clean.
func Evaluate(ev Evidence) Verdict {
	var v Verdict
	seen := map[string]bool{}
	add := func(code, source string) {
		if seen[code] {
			return
		}
		seen[code] = true
		v.Causes = append(v.Causes, Cause{Code: code, Source: source, Fixes: FixesFor(code)})
	}

	bundle := ev.Bundle
	if bundle != nil && !ev.Now.IsZero() && ev.Now.Sub(bundle.CollectedAt) > StaleBundle {
		bundle, v.BundleStale = nil, true
	}

	// The server's record of the device outranks what the device believes.
	switch d := ev.Device; {
	case d == nil:
		if bundle == nil || !bundle.failed("NOT_ENROLLED") {
			add(CauseNoDevice, "server")
		}
	case d.Status == DeviceRevoked:
		add(CauseDeviceRevoked, "server")
	case d.Status == DeviceSuspended:
		add(CauseDeviceSuspended, "server")
	case d.Status == DevicePending:
		add(CauseDevicePending, "server")
	}

	if bundle != nil {
		for _, c := range bundle.Checks {
			if c.Status != StatusFail {
				continue
			}
			if cause, ok := bundleCauses[c.Code]; ok {
				add(cause, "device")
			}
		}
	}

	if d := ev.Device; d != nil && d.Status == DeviceActive {
		// A device that sent a fresh bundle is plainly not offline.
		if !d.Live && bundle == nil {
			add(CauseDeviceOffline, "server")
		}
		if d.Live && bundle == nil {
			switch d.TunnelState {
			case "degraded":
				add(CauseTunnelDown, "server")
			case "not_installed":
				add(CauseTunnelNotInstalled, "server")
			}
		}
		if d.Outdated {
			add(CauseAgentOutdated, "server")
		}
		needsTrust := ev.Access == nil || ev.Access.DeviceTrustRequired
		if d.Compliant != nil && !*d.Compliant && needsTrust {
			add(CausePostureFail, "server")
		}
	}

	if a := ev.Access; a != nil {
		if !a.Assigned {
			add(CauseNotAssigned, "server")
		} else if a.StepUpRequired {
			add(CauseStepUpRequired, "server")
		}
	}

	// The service's own side matters only to someone who is allowed to use it.
	if s := ev.Service; s != nil && (ev.Access == nil || ev.Access.Assigned) {
		switch {
		case !s.Exists || !s.HasTerminator:
			add(CauseServiceNoTerminator, "server")
		case !s.DialAllowed && !seen[CausePostureFail]:
			add(CausePolicyGap, "server")
		}
	}

	sort.SliceStable(v.Causes, func(i, j int) bool {
		return catalog[v.Causes[i].Code].rank < catalog[v.Causes[j].Code].rank
	})
	if len(v.Causes) > 0 {
		return v
	}
	// Nothing found. That is "healthy" only if we could see the device's side.
	if bundle != nil || (ev.Device != nil && ev.Device.Live) {
		v.Healthy = true
		v.Causes = []Cause{}
		return v
	}
	add(CauseUnknown, "server")
	return v
}

func sortByRank(codes []string) {
	sort.Slice(codes, func(i, j int) bool { return catalog[codes[i]].rank < catalog[codes[j]].rank })
}
