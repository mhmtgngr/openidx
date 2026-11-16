package diagnose

// Cause codes: why a person on a device cannot reach what they expect to.
// The console and the clients carry the wording for each (en and tr) under
// diagnose.cause.<code>; this package decides only which apply.
const (
	// The device and its enrolment.
	CauseNoDevice          = "NO_DEVICE"
	CauseNotEnrolled       = "NOT_ENROLLED"
	CauseDevicePending     = "DEVICE_PENDING"
	CauseDeviceRevoked     = "DEVICE_REVOKED"
	CauseDeviceSuspended   = "DEVICE_SUSPENDED"
	CauseAuthInvalid       = "AUTH_INVALID"
	CauseIdentityExpired   = "IDENTITY_EXPIRED"
	CauseAgentOutdated     = "AGENT_OUTDATED"
	CauseServiceNotRunning = "SERVICE_NOT_RUNNING"
	CauseDeviceOffline     = "DEVICE_OFFLINE"

	// The device's network.
	CauseDNSFail        = "DNS_FAIL"
	CauseNetworkBlocked = "NETWORK_BLOCKED"
	CauseTLSIntercepted = "TLS_INTERCEPTED"
	CauseProxyBlock     = "PROXY_BLOCK"
	CauseClockSkew      = "CLOCK_SKEW"
	CauseServerError    = "SERVER_ERROR"

	// The tunnel.
	CauseTunnelDown         = "TUNNEL_DOWN"
	CauseTunnelNotInstalled = "TUNNEL_NOT_INSTALLED"

	// What the person is allowed.
	CausePostureFail    = "POSTURE_FAIL"
	CauseNotAssigned    = "NOT_ASSIGNED"
	CauseStepUpRequired = "STEPUP_REQUIRED"

	// The service's own side: nothing the person or the device can fix.
	CauseServiceNoTerminator = "SERVICE_NO_TERMINATOR"
	CausePolicyGap           = "POLICY_GAP"

	// Evidence was gathered and nothing in it explains the failure.
	CauseUnknown = "UNKNOWN"
)

// Tier says who may carry out a fix.
type Tier string

const (
	// TierUser: only the person at the device can do it.
	TierUser Tier = "user_action"
	// TierSafeFix: reversible, on the person's own device; may run without
	// asking when the organization allows it.
	TierSafeFix Tier = "safe_fix"
	// TierApproval: changes access, policy or the network; a human approves.
	TierApproval Tier = "needs_approval"
)

// Fix actions.
const (
	FixEnrollDevice    = "enroll_device"
	FixReenroll        = "reenroll"
	FixRestartTunnel   = "restart_tunnel"
	FixRestartAgent    = "restart_agent"
	FixUpdateAgent     = "update_agent"
	FixCollectLogs     = "collect_logs"
	FixInstallTunnel   = "reinstall_agent"
	FixChangeNetwork   = "change_network"
	FixSignInToNetwork = "sign_in_to_network"
	FixSetClock        = "set_clock"
	FixAskProxy        = "ask_proxy_settings"
	FixWait            = "wait_and_retry"
	FixPosture         = "fix_posture"
	FixStepUp          = "complete_stepup"
	FixTurnDeviceOn    = "open_agent"
	FixRequestAccess   = "request_access"
	FixApproveDevice   = "approve_device"
	FixReinstateDevice = "reinstate_device"
	FixServiceHosting  = "fix_service_hosting"
	FixServicePolicy   = "fix_service_policy"
	FixContactIT       = "contact_it"
)

// Fix is one thing that addresses a cause.
type Fix struct {
	Action string `json:"action"`
	Tier   Tier   `json:"tier"`
}

type causeSpec struct {
	// rank orders causes in a verdict: lower explains more, so it goes first.
	rank  int
	fixes []Fix
}

func fx(action string, tier Tier) Fix { return Fix{Action: action, Tier: tier} }

// catalog is every cause, its rank and its fixes. Rank groups: a device that
// is refused outright (1x), one that is not there at all (2x), its network
// (3x), its software and tunnel (4x), what the person is allowed (5x), the
// service's own side (6x).
var catalog = map[string]causeSpec{
	CauseDeviceRevoked:   {10, []Fix{fx(FixReinstateDevice, TierApproval), fx(FixContactIT, TierUser)}},
	CauseDeviceSuspended: {11, []Fix{fx(FixPosture, TierUser), fx(FixReinstateDevice, TierApproval)}},
	CauseDevicePending:   {12, []Fix{fx(FixApproveDevice, TierApproval)}},
	CauseNoDevice:        {13, []Fix{fx(FixEnrollDevice, TierUser)}},
	CauseNotEnrolled:     {14, []Fix{fx(FixEnrollDevice, TierUser)}},
	CauseAuthInvalid:     {15, []Fix{fx(FixReenroll, TierSafeFix), fx(FixEnrollDevice, TierUser)}},

	CauseServiceNotRunning: {20, []Fix{fx(FixRestartAgent, TierUser)}},
	CauseDeviceOffline:     {21, []Fix{fx(FixTurnDeviceOn, TierUser)}},

	CauseClockSkew:      {30, []Fix{fx(FixSetClock, TierUser)}},
	CauseDNSFail:        {31, []Fix{fx(FixChangeNetwork, TierUser)}},
	CauseTLSIntercepted: {32, []Fix{fx(FixSignInToNetwork, TierUser), fx(FixContactIT, TierUser)}},
	CauseProxyBlock:     {33, []Fix{fx(FixAskProxy, TierUser)}},
	CauseNetworkBlocked: {34, []Fix{fx(FixChangeNetwork, TierUser)}},
	CauseServerError:    {35, []Fix{fx(FixWait, TierUser)}},

	CauseIdentityExpired:    {40, []Fix{fx(FixReenroll, TierSafeFix)}},
	CauseTunnelNotInstalled: {41, []Fix{fx(FixInstallTunnel, TierUser)}},
	CauseTunnelDown:         {42, []Fix{fx(FixRestartTunnel, TierSafeFix), fx(FixCollectLogs, TierSafeFix)}},
	CauseAgentOutdated:      {43, []Fix{fx(FixUpdateAgent, TierSafeFix)}},

	CausePostureFail:    {50, []Fix{fx(FixPosture, TierUser)}},
	CauseNotAssigned:    {51, []Fix{fx(FixRequestAccess, TierApproval)}},
	CauseStepUpRequired: {52, []Fix{fx(FixStepUp, TierUser)}},

	CauseServiceNoTerminator: {60, []Fix{fx(FixServiceHosting, TierApproval)}},
	CausePolicyGap:           {61, []Fix{fx(FixServicePolicy, TierApproval)}},

	CauseUnknown: {99, []Fix{fx(FixCollectLogs, TierSafeFix), fx(FixContactIT, TierUser)}},
}

// AllCauses lists every cause code, for the wording tables to be checked
// against.
func AllCauses() []string {
	out := make([]string, 0, len(catalog))
	for code := range catalog {
		out = append(out, code)
	}
	sortByRank(out)
	return out
}

// FixesFor returns the fixes for a cause, or nil for an unknown code.
func FixesFor(code string) []Fix {
	return append([]Fix(nil), catalog[code].fixes...)
}
