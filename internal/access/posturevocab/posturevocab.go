// Package posturevocab is the one place the server names the posture-check
// types it knows, and says which of two vocabularies each one belongs to.
//
// WHY THERE ARE TWO. One table, posture_checks, holds two kinds of row that
// share nothing but the table:
//
//   - Ziti posture checks (OS, Domain, MFA, Process, MAC) are objects on the
//     OpenZiti controller. The console writes them in the controller's
//     vocabulary and the access service mirrors each one to the controller,
//     which enforces it when an identity dials a service.
//   - Device agent checks (disk_encryption, os_version, play_integrity, ...)
//     are run by the OpenIDX agents on the device. GET /agent/config serves
//     them, the agent runs them, and the report it files drives compliance,
//     the grace period and, under POSTURE_DEVICE_TRUST_GATE=enforce, the
//     device-trusted attribute.
//
// Nothing used to tell the two apart. The console could only author Ziti rows,
// the config endpoint served every row to every agent, and an agent handed
// "OS" answered "unknown check type". The kind of a row is derived from its
// check_type here, so neither side needs a column to remember it, and the two
// vocabularies cannot overlap without the tests in this package failing.
//
// The agent half is pinned to the agents themselves: tools/posturevocab
// compares AgentChecks with the check types the Go and Kotlin agents
// register, the platforms each one can examine and the params the Go checks
// read, and fails CI when they disagree.
package posturevocab

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Kind says which vocabulary a check_type belongs to.
type Kind string

const (
	// KindAgent is a check an OpenIDX agent runs on the device.
	KindAgent Kind = "agent"
	// KindZiti is a posture check the OpenZiti controller enforces.
	KindZiti Kind = "ziti"
)

// zitiTypeIDs maps every spelling of a Ziti posture check type the service
// accepts to the typeId the controller's management API takes. The console
// writes the mixed-case names; the controller's own uppercase ids are accepted
// too, because API callers have always been able to send them and the
// controller understood them.
var zitiTypeIDs = map[string]string{
	"OS":      "OS",
	"Domain":  "DOMAIN",
	"DOMAIN":  "DOMAIN",
	"MFA":     "MFA",
	"Process": "PROCESS",
	"PROCESS": "PROCESS",
	"MAC":     "MAC",
}

// zitiConsoleTypes are the spellings the console offers, in its order.
var zitiConsoleTypes = []string{"OS", "Domain", "MFA", "Process", "MAC"}

// ParamKind is the JSON shape a param takes.
type ParamKind string

const (
	// ParamVersion is a dot-separated run of numbers such as "10.0.19045".
	// The Go agent compares versions numerically and stops at the first part
	// that is not a number, so "v10" would compare as nothing at all and
	// every device would pass. Only digits and dots are accepted.
	ParamVersion ParamKind = "version"
	// ParamInteger is a whole JSON number between Min and Max.
	ParamInteger ParamKind = "integer"
	// ParamBoolean is a JSON true or false.
	ParamBoolean ParamKind = "boolean"
	// ParamStringList is a JSON array of non-empty strings, at most Max long.
	ParamStringList ParamKind = "string_list"
)

// Param is one key a check's params object may carry.
type Param struct {
	Name     string    `json:"name"`
	Kind     ParamKind `json:"kind"`
	Required bool      `json:"required,omitempty"`
	// Min and Max bound an integer. For a string list Max is the most entries
	// it may hold.
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
}

// AgentCheck describes one device agent check type.
type AgentCheck struct {
	Type string `json:"type"`
	// Platforms are the device platforms some shipped agent can examine this
	// check on, named as enrolled_agents.platform names them. A row may be
	// scoped to these and no others.
	Platforms []string `json:"platforms"`
	// Params are the keys its params object may carry. A key not listed here
	// is refused: the agent would ignore it, and an administrator who typed
	// it believes it does something.
	Params []Param `json:"params"`
}

// Device platforms, as normalizePlatform in internal/access stores them in
// enrolled_agents.platform. GET /agent/config matches a row's platforms
// against that column, so a row scoped to any other spelling ("Windows",
// "darwin") would never reach a device.
const (
	PlatformWindows = "windows"
	PlatformMacOS   = "macos"
	PlatformLinux   = "linux"
	PlatformAndroid = "android"
	PlatformIOS     = "ios"
	// PlatformAny is the explicit "every platform" marker the config query
	// also accepts. An empty platforms list means the same.
	PlatformAny = "any"
)

var (
	desktops         = []string{PlatformWindows, PlatformMacOS, PlatformLinux}
	desktopsAndDroid = []string{PlatformWindows, PlatformMacOS, PlatformLinux, PlatformAndroid}
	everyPlatform    = []string{PlatformWindows, PlatformMacOS, PlatformLinux, PlatformAndroid, PlatformIOS}
	androidOnly      = []string{PlatformAndroid}
	linuxOnly        = []string{PlatformLinux}
)

// minVersion is the min_version param os_version and agent_version share.
var minVersion = Param{Name: "min_version", Kind: ParamVersion}

// agentChecks is the agent vocabulary. tools/posturevocab holds it against the
// agents' source: every type a shipped agent registers is here and nothing
// else is, each Platforms list is exactly where an agent can examine the
// check, and each Go check's Params are exactly the keys its code reads.
//
// Platforms follow where the check is implemented, not where it is wanted:
// process_running reads /proc and declines on every other platform, and
// integrity has a Linux implementation only, so neither may be scoped to
// windows.
//
// The Android agent runs os_version, patch_level, agent_version and its other
// checks with built-in thresholds and reads no params. play_integrity's params
// are read by the server, which judges the verdict Google returns
// (internal/access/play_integrity.go IntegrityPolicy).
var agentChecks = []AgentCheck{
	{Type: "accessibility_audit", Platforms: androidOnly},
	{Type: "agent_version", Platforms: everyPlatform, Params: []Param{minVersion}},
	{Type: "antivirus", Platforms: desktops},
	{Type: "developer_options", Platforms: androidOnly},
	{Type: "disk_encryption", Platforms: desktopsAndDroid},
	{Type: "domain_joined", Platforms: desktops},
	{Type: "enterprise_managed", Platforms: androidOnly},
	{Type: "firewall", Platforms: desktops},
	{Type: "integrity", Platforms: linuxOnly},
	{Type: "os_version", Platforms: desktopsAndDroid, Params: []Param{minVersion}},
	{Type: "patch_level", Platforms: desktopsAndDroid, Params: []Param{
		{Name: "max_days", Kind: ParamInteger, Min: 1, Max: 3650},
	}},
	{Type: "play_integrity", Platforms: androidOnly, Params: []Param{
		{Name: "require_meets_basic_integrity", Kind: ParamBoolean},
		{Name: "require_meets_device_integrity", Kind: ParamBoolean},
		{Name: "require_meets_strong_integrity", Kind: ParamBoolean},
		{Name: "require_play_recognized", Kind: ParamBoolean},
	}},
	// processes is required: with none listed the check passes on every
	// device, which is a check in name only.
	{Type: "process_running", Platforms: linuxOnly, Params: []Param{
		{Name: "processes", Kind: ParamStringList, Required: true, Max: 64},
	}},
	{Type: "screen_lock", Platforms: desktopsAndDroid},
	{Type: "unknown_sources", Platforms: androidOnly},
}

var agentByType = func() map[string]AgentCheck {
	m := make(map[string]AgentCheck, len(agentChecks))
	for _, c := range agentChecks {
		m[c.Type] = c
	}
	return m
}()

// Severities are the values the report path scores (severityWeight and
// enforcementAction in internal/access/agent_api.go): a failing critical
// check makes the device non_compliant, a failing high one starts its grace
// period, medium alerts, low only weighs in the score.
var severities = []string{"low", "medium", "high", "critical"}

// KindOf returns the vocabulary checkType belongs to, or "" when it belongs
// to neither.
func KindOf(checkType string) Kind {
	if _, ok := agentByType[checkType]; ok {
		return KindAgent
	}
	if _, ok := zitiTypeIDs[checkType]; ok {
		return KindZiti
	}
	return ""
}

// ZitiTypeID returns the controller typeId for a Ziti posture check type.
func ZitiTypeID(checkType string) (string, bool) {
	id, ok := zitiTypeIDs[checkType]
	return id, ok
}

// ZitiTypes returns the Ziti posture check types as the console spells them.
func ZitiTypes() []string {
	return append([]string(nil), zitiConsoleTypes...)
}

// AgentChecks returns the agent vocabulary, sorted by type. The slices are
// copies, so a caller cannot change the vocabulary by editing the result.
func AgentChecks() []AgentCheck {
	out := make([]AgentCheck, len(agentChecks))
	for i, c := range agentChecks {
		out[i] = AgentCheck{
			Type:      c.Type,
			Platforms: append([]string(nil), c.Platforms...),
			Params:    append([]Param{}, c.Params...),
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Severities returns the severities an agent check may carry, least severe
// first.
func Severities() []string { return append([]string(nil), severities...) }

// Platforms returns the device platforms a row may be scoped to, not
// counting the "any" marker.
func Platforms() []string { return append([]string(nil), everyPlatform...) }

// Error is a validation failure: Code is stable for a client to branch on,
// Field names what was wrong and Message says it in a sentence.
type Error struct {
	Code    string
	Field   string
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code, field, format string, args ...interface{}) *Error {
	return &Error{Code: code, Field: field, Message: fmt.Sprintf(format, args...)}
}

// Validation codes.
const (
	CodeUnknownCheckType     = "unknown_check_type"
	CodeInvalidName          = "invalid_name"
	CodeInvalidSeverity      = "invalid_severity"
	CodeInvalidPlatform      = "invalid_platform"
	CodePlatformNotSupported = "platform_not_supported"
	CodeUnknownParam         = "unknown_param"
	CodeMissingParam         = "missing_param"
	CodeInvalidParam         = "invalid_param"
)

// maxNameLen is posture_checks.name's VARCHAR(255).
const maxNameLen = 255

// maxListEntryLen bounds one entry of a string list. A process name is far
// shorter; the bound is what keeps a pasted blob out of every agent's config.
const maxListEntryLen = 256

var versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// ValidateAgentCheck reports the first thing wrong with an agent check row, or
// nil when GET /agent/config can serve it as written. The order is fixed so a
// client sees the same error for the same input.
func ValidateAgentCheck(name, checkType string, params map[string]interface{}, severity string, platforms []string) *Error {
	spec, ok := agentByType[checkType]
	if !ok {
		return fail(CodeUnknownCheckType, "check_type",
			"check_type %q is not a device agent check", checkType)
	}
	if strings.TrimSpace(name) == "" {
		return fail(CodeInvalidName, "name", "name is required")
	}
	if len(name) > maxNameLen {
		return fail(CodeInvalidName, "name", "name is longer than %d characters", maxNameLen)
	}
	if !contains(severities, severity) {
		return fail(CodeInvalidSeverity, "severity",
			"severity must be one of %s", strings.Join(severities, ", "))
	}
	for _, p := range platforms {
		if p == PlatformAny {
			continue
		}
		if !contains(everyPlatform, p) {
			return fail(CodeInvalidPlatform, "platforms",
				"platform %q is not one of %s, %s", p, strings.Join(everyPlatform, ", "), PlatformAny)
		}
		if !contains(spec.Platforms, p) {
			return fail(CodePlatformNotSupported, "platforms",
				"%s cannot run on %s: no OpenIDX agent implements it there (it runs on %s)",
				checkType, p, strings.Join(spec.Platforms, ", "))
		}
	}
	return validateParams(spec, params)
}

func validateParams(spec AgentCheck, params map[string]interface{}) *Error {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := paramNamed(spec, k); !ok {
			if len(spec.Params) == 0 {
				return fail(CodeUnknownParam, "parameters."+k,
					"%s takes no params, so %q would be ignored", spec.Type, k)
			}
			names := make([]string, len(spec.Params))
			for i, p := range spec.Params {
				names[i] = p.Name
			}
			return fail(CodeUnknownParam, "parameters."+k,
				"%s does not read %q; it takes %s", spec.Type, k, strings.Join(names, ", "))
		}
	}
	for _, p := range spec.Params {
		v, present := params[p.Name]
		if !present || v == nil {
			if p.Required {
				return fail(CodeMissingParam, "parameters."+p.Name, "%s requires %s", spec.Type, p.Name)
			}
			continue
		}
		if err := validateParam(p, v); err != nil {
			return err
		}
	}
	return nil
}

func validateParam(p Param, v interface{}) *Error {
	field := "parameters." + p.Name
	switch p.Kind {
	case ParamVersion:
		s, ok := v.(string)
		if !ok || len(s) > 64 || !versionPattern.MatchString(s) {
			return fail(CodeInvalidParam, field,
				"%s must be a version made of numbers and dots, such as 10.0.19045", p.Name)
		}
	case ParamInteger:
		n, ok := v.(float64)
		if !ok || n != math.Trunc(n) || n < float64(p.Min) || n > float64(p.Max) {
			return fail(CodeInvalidParam, field,
				"%s must be a whole number from %d to %d", p.Name, p.Min, p.Max)
		}
	case ParamBoolean:
		if _, ok := v.(bool); !ok {
			return fail(CodeInvalidParam, field, "%s must be true or false", p.Name)
		}
	case ParamStringList:
		list, ok := v.([]interface{})
		if !ok {
			return fail(CodeInvalidParam, field, "%s must be a list of names", p.Name)
		}
		if p.Required && len(list) == 0 {
			return fail(CodeMissingParam, field, "%s must name at least one entry", p.Name)
		}
		if p.Max > 0 && len(list) > p.Max {
			return fail(CodeInvalidParam, field, "%s may hold at most %d entries", p.Name, p.Max)
		}
		for _, item := range list {
			s, ok := item.(string)
			if !ok || strings.TrimSpace(s) == "" || len(s) > maxListEntryLen {
				return fail(CodeInvalidParam, field,
					"every entry of %s must be a non-empty name of at most %d characters", p.Name, maxListEntryLen)
			}
		}
	default:
		// A kind added to the vocabulary without a rule here would let any
		// value through, so it is refused until it has one.
		return fail(CodeInvalidParam, field, "%s has no validation rule", p.Name)
	}
	return nil
}

func paramNamed(spec AgentCheck, name string) (Param, bool) {
	for _, p := range spec.Params {
		if p.Name == name {
			return p, true
		}
	}
	return Param{}, false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
