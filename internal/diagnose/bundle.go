// Package diagnose turns evidence about a device that cannot connect into a
// verdict: an ordered list of causes, each with the fixes that address it.
// It is pure rules over plain data. It reads no database and calls no model;
// whatever narrates a verdict later may reword it and may not change it.
package diagnose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// BundleSchema is the diagnostic bundle version this server understands. The
// agent's copy of these types is agent/internal/doctor; the two modules
// cannot import each other, and TestBundleMatchesTheAgentsWireFormat holds
// them together.
const BundleSchema = 1

// Limits on what a device may send. A bundle comes from a machine the server
// does not control: every count and every string is bounded before use.
const (
	MaxBundleBytes = 64 << 10
	maxChecks      = 32
	maxRepairs     = 16
	maxServices    = 256
	maxText        = 200
)

// Check statuses.
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusWarn    = "warn"
	StatusSkipped = "skipped"
)

// Check is one finding of the device's doctor.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
	Millis int64  `json:"ms"`
}

// Repair is one local fix the device tried or would try.
type Repair struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Tunnel is the tunneler's own report.
type Tunnel struct {
	State         string     `json:"state"`
	Version       string     `json:"version"`
	LastSeen      *time.Time `json:"last_seen"`
	Services      []string   `json:"services"`
	Mode          string     `json:"mode,omitempty"`
	PolicyVersion string     `json:"policy_version,omitempty"`
	PolicyGaps    []string   `json:"policy_gaps,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// Enrollment is what the device knows about its own enrolment.
type Enrollment struct {
	Enrolled     bool       `json:"enrolled"`
	AuthInvalid  bool       `json:"auth_invalid"`
	Revoked      bool       `json:"revoked"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
}

// Net describes the device's path to the server.
type Net struct {
	ProxyMode string `json:"proxy_mode"`
	ProxyHost string `json:"proxy_host,omitempty"`
	DNSOK     bool   `json:"dns_ok"`
}

// Bundle is the diagnostic bundle, schema v1.
type Bundle struct {
	Schema       int        `json:"schema"`
	AgentID      string     `json:"agent_id,omitempty"`
	AgentVersion string     `json:"agent_version"`
	OS           string     `json:"os"`
	CollectedAt  time.Time  `json:"collected_at"`
	ClockSkewS   *int64     `json:"clock_skew_s,omitempty"`
	Checks       []Check    `json:"checks"`
	Repairs      []Repair   `json:"repairs"`
	Tunnel       *Tunnel    `json:"tunnel,omitempty"`
	Enrollment   Enrollment `json:"enrollment"`
	Net          Net        `json:"net"`
}

// ErrBundle is wrapped by every reason ParseBundle refuses a bundle.
var ErrBundle = errors.New("invalid diagnostic bundle")

// ParseBundle decodes and bounds a bundle a device sent. Unknown fields are
// refused, so a newer agent must raise the schema rather than slip data past
// a server that would ignore it. Free text is clipped, never trusted: it is
// device-supplied and may be shown to an operator or handed to a model.
func ParseBundle(raw []byte) (*Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrBundle, MaxBundleBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrBundle)
	}
	switch {
	case b.Schema != BundleSchema:
		return nil, fmt.Errorf("%w: schema %d is not %d", ErrBundle, b.Schema, BundleSchema)
	case len(b.Checks) > maxChecks || len(b.Repairs) > maxRepairs:
		return nil, fmt.Errorf("%w: too many entries", ErrBundle)
	case b.Tunnel != nil && (len(b.Tunnel.Services) > maxServices || len(b.Tunnel.PolicyGaps) > maxChecks):
		return nil, fmt.Errorf("%w: too many entries", ErrBundle)
	}
	for i := range b.Checks {
		c := &b.Checks[i]
		switch c.Status {
		case StatusPass, StatusFail, StatusWarn, StatusSkipped:
		default:
			return nil, fmt.Errorf("%w: unknown check status", ErrBundle)
		}
		c.ID, c.Code, c.Detail = clip(c.ID), clip(c.Code), clip(c.Detail)
	}
	for i := range b.Repairs {
		r := &b.Repairs[i]
		r.ID, r.Outcome, r.Detail = clip(r.ID), clip(r.Outcome), clip(r.Detail)
	}
	b.AgentID, b.AgentVersion, b.OS = clip(b.AgentID), clip(b.AgentVersion), clip(b.OS)
	b.Net.ProxyMode, b.Net.ProxyHost = clip(b.Net.ProxyMode), clip(b.Net.ProxyHost)
	if t := b.Tunnel; t != nil {
		t.State, t.Version, t.Mode = clip(t.State), clip(t.Version), clip(t.Mode)
		t.PolicyVersion, t.LastError = clip(t.PolicyVersion), clip(t.LastError)
		for i := range t.Services {
			t.Services[i] = clip(t.Services[i])
		}
		for i := range t.PolicyGaps {
			t.PolicyGaps[i] = clip(t.PolicyGaps[i])
		}
	}
	return &b, nil
}

func clip(s string) string {
	r := []rune(s)
	if len(r) > maxText {
		return string(r[:maxText])
	}
	return s
}

// failed reports whether the bundle carries a failing check with this code.
func (b *Bundle) failed(code string) bool {
	if b == nil {
		return false
	}
	for _, c := range b.Checks {
		if c.Status == StatusFail && c.Code == code {
			return true
		}
	}
	return false
}
