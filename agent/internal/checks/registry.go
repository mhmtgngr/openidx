package checks

import (
	"context"
	"encoding/json"
	"sort"
)

// CheckConfig describes a single security check to run on the device.
type CheckConfig struct {
	Type     string                 `json:"type"`
	Params   map[string]interface{} `json:"params,omitempty"`
	Severity string                 `json:"severity"`
	Interval string                 `json:"interval"`
	// Disabled is true when the server lists the check with enabled:false.
	// The engine skips it rather than reporting a result nobody asked for.
	Disabled bool `json:"-"`
}

// UnmarshalJSON reads the access service's wire shape as well as this
// struct's own. The server sends each check as {name, enabled, check_type,
// severity, params} (internal/access/agent_api.go agentCheck), the shape the
// Android agent reads; this struct only knew "type", so every check the
// server configured reached the engine with an empty type and ran as
// "unknown check type". The type is the first of type, check_type and name
// that is set. A params value that is not a JSON object is ignored rather
// than failing the whole config, which would drop every other check too.
func (c *CheckConfig) UnmarshalJSON(b []byte) error {
	var w struct {
		Type      string          `json:"type"`
		CheckType string          `json:"check_type"`
		Name      string          `json:"name"`
		Params    json.RawMessage `json:"params"`
		Severity  string          `json:"severity"`
		Interval  string          `json:"interval"`
		Enabled   *bool           `json:"enabled"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*c = CheckConfig{Severity: w.Severity, Interval: w.Interval}
	for _, t := range []string{w.Type, w.CheckType, w.Name} {
		if t != "" {
			c.Type = t
			break
		}
	}
	if len(w.Params) > 0 {
		var params map[string]interface{}
		if json.Unmarshal(w.Params, &params) == nil {
			c.Params = params
		}
	}
	c.Disabled = w.Enabled != nil && !*w.Enabled
	return nil
}

// Status represents the outcome of a security check.
type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

// CheckResult holds the output of a single check execution.
type CheckResult struct {
	Status      Status                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`

	// Unsupported marks a result that says nothing about the device: the check
	// has no implementation for this operating system and did not run.
	//
	// It exists because "we could not measure this" and "we measured it and it
	// is a bit concerning" were the same value. Seven checks answer an
	// unimplemented platform with StatusWarn, and warns do not count against
	// compliance -- so on Android and iOS, where none of disk_encryption,
	// screen_lock, patch_level, firewall, antivirus, domain_joined or integrity
	// has an implementation, a device could be reported COMPLIANT on the
	// strength of checks that never executed. disk_encryption is configured
	// "critical".
	//
	// The Status stays warn so the wire format and the server's ingest are
	// unchanged; this flag is the extra fact a caller needs to avoid counting
	// a gap in the measurement as a clean result.
	Unsupported bool `json:"unsupported,omitempty"`
}

// Check is the interface that every security check must implement.
type Check interface {
	Name() string
	Run(ctx context.Context, params map[string]interface{}) *CheckResult
}

// Registry holds a named collection of Check implementations.
type Registry struct {
	checks map[string]Check
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		checks: make(map[string]Check),
	}
}

// Register adds check to the registry under the given name, overwriting any
// previous registration with the same name.
func (r *Registry) Register(name string, check Check) {
	r.checks[name] = check
}

// Get returns the Check registered under name and a boolean indicating whether
// it was found.
func (r *Registry) Get(name string) (Check, bool) {
	c, ok := r.checks[name]
	return c, ok
}

// List returns the names of all registered checks in sorted order.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.checks))
	for name := range r.checks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
