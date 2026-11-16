// Package doctor diagnoses, on the device and without the server's help, why
// this agent cannot connect. It produces a versioned diagnostic bundle, a
// plain-language explanation, and a small set of safe local repairs.
//
// The bundle never carries secrets: no auth token, no enrollment token, no
// proxy credentials, no key material and no log bodies.
package doctor

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

// SchemaVersion is the bundle's wire version. The server keeps a mirror of
// these types; a change here needs the same change there.
const SchemaVersion = 1

// CheckStatus is one check's outcome.
type CheckStatus string

const (
	StatusPass    CheckStatus = "pass"
	StatusFail    CheckStatus = "fail"
	StatusWarn    CheckStatus = "warn"
	StatusSkipped CheckStatus = "skipped"
)

// Check IDs, in the order a bundle always lists them.
const (
	CheckConfig      = "config"
	CheckCredentials = "credentials"
	CheckDNS         = "dns"
	CheckTCP         = "tcp"
	CheckTLS         = "tls"
	CheckHTTP        = "http"
	CheckClock       = "clock"
	CheckIdentity    = "identity"
	CheckService     = "service"
	CheckTunnel      = "tunnel"
)

// CheckOrder is every check ID in bundle order.
var CheckOrder = []string{
	CheckConfig, CheckCredentials, CheckDNS, CheckTCP, CheckTLS,
	CheckHTTP, CheckClock, CheckIdentity, CheckService, CheckTunnel,
}

// Cause codes a check can report.
const (
	CodeConfigUnreadable   = "CONFIG_UNREADABLE"
	CodeNotEnrolled        = "NOT_ENROLLED"
	CodeAuthInvalid        = "AUTH_INVALID"
	CodeDeviceRevoked      = "DEVICE_REVOKED"
	CodeDNSFail            = "DNS_FAIL"
	CodeDNSTimeout         = "DNS_TIMEOUT"
	CodeTCPBlocked         = "TCP_BLOCKED"
	CodeTCPTimeout         = "TCP_TIMEOUT"
	CodeTLSUntrusted       = "TLS_UNTRUSTED"
	CodeTLSFail            = "TLS_FAIL"
	CodeProxyAuthRequired  = "PROXY_AUTH_REQUIRED"
	CodeServerHTTPError    = "SERVER_HTTP_ERROR"
	CodeHTTPTimeout        = "HTTP_TIMEOUT"
	CodeHTTPFail           = "HTTP_FAIL"
	CodeClockSkew          = "CLOCK_SKEW"
	CodeIdentityMissing    = "IDENTITY_MISSING"
	CodeIdentityExpired    = "IDENTITY_EXPIRED"
	CodeIdentityExpiring   = "IDENTITY_EXPIRING"
	CodeIdentityInvalid    = "IDENTITY_INVALID"
	CodeServiceNotRunning  = "SERVICE_NOT_RUNNING"
	CodeTunnelDown         = "TUNNEL_DOWN"
	CodeTunnelNotInstalled = "TUNNEL_NOT_INSTALLED"
	CodeTunnelOff          = "TUNNEL_OFF"
	CodeInternal           = "INTERNAL"
)

// AllCodes lists every code; the string tables are checked against it.
var AllCodes = []string{
	CodeConfigUnreadable, CodeNotEnrolled, CodeAuthInvalid, CodeDeviceRevoked,
	CodeDNSFail, CodeDNSTimeout, CodeTCPBlocked, CodeTCPTimeout,
	CodeTLSUntrusted, CodeTLSFail, CodeProxyAuthRequired, CodeServerHTTPError,
	CodeHTTPTimeout, CodeHTTPFail, CodeClockSkew, CodeIdentityMissing,
	CodeIdentityExpired, CodeIdentityExpiring, CodeIdentityInvalid,
	CodeServiceNotRunning, CodeTunnelDown, CodeTunnelNotInstalled,
	CodeTunnelOff, CodeInternal,
}

// Repair IDs and outcomes.
const (
	RepairFlushDNS       = "flush_dns"
	RepairRestartService = "restart_service"

	OutcomePlanned        = "planned"
	OutcomeApplied        = "applied"
	OutcomeFailed         = "failed"
	OutcomeNeedsElevation = "needs_elevation"
)

const maxDetail = 200

// Check is one finding.
type Check struct {
	ID     string      `json:"id"`
	Status CheckStatus `json:"status"`
	Code   string      `json:"code,omitempty"`
	Detail string      `json:"detail,omitempty"`
	Millis int64       `json:"ms"`
}

// Repair is one local fix and what became of it.
type Repair struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Enrollment is what the device knows about its own enrolment.
type Enrollment struct {
	Enrolled     bool       `json:"enrolled"`
	AuthInvalid  bool       `json:"auth_invalid"`
	Revoked      bool       `json:"revoked"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
}

// Net describes the path to the server.
type Net struct {
	ProxyMode string `json:"proxy_mode"`
	ProxyHost string `json:"proxy_host,omitempty"`
	DNSOK     bool   `json:"dns_ok"`
}

// Bundle is the diagnostic bundle, schema v1.
type Bundle struct {
	Schema       int            `json:"schema"`
	AgentID      string         `json:"agent_id,omitempty"`
	AgentVersion string         `json:"agent_version"`
	OS           string         `json:"os"`
	CollectedAt  time.Time      `json:"collected_at"`
	ClockSkewS   *int64         `json:"clock_skew_s,omitempty"`
	Checks       []Check        `json:"checks"`
	Repairs      []Repair       `json:"repairs"`
	Tunnel       *tunnel.Status `json:"tunnel,omitempty"`
	Enrollment   Enrollment     `json:"enrollment"`
	Net          Net            `json:"net"`
}

// NewBundle starts an empty bundle stamped with now.
func NewBundle(agentID, version string, now time.Time) Bundle {
	return Bundle{
		Schema:       SchemaVersion,
		AgentID:      agentID,
		AgentVersion: version,
		OS:           runtime.GOOS,
		CollectedAt:  now.UTC(),
		Checks:       []Check{},
		Repairs:      []Repair{},
		Net:          Net{ProxyMode: "none"},
	}
}

// MarshalJSON keeps checks and repairs as arrays even when empty.
func (b Bundle) MarshalJSON() ([]byte, error) {
	type plain Bundle
	p := plain(b)
	if p.Checks == nil {
		p.Checks = []Check{}
	}
	if p.Repairs == nil {
		p.Repairs = []Repair{}
	}
	return json.Marshal(p)
}

// Failing returns the failed checks, in order.
func (b Bundle) Failing() []Check {
	var out []Check
	for _, c := range b.Checks {
		if c.Status == StatusFail {
			out = append(out, c)
		}
	}
	return out
}

// Healthy reports whether no check failed.
func (b Bundle) Healthy() bool { return len(b.Failing()) == 0 }

// clip bounds free text that ends up in a bundle.
func clip(s string) string {
	r := []rune(s)
	if len(r) > maxDetail {
		return string(r[:maxDetail])
	}
	return s
}
