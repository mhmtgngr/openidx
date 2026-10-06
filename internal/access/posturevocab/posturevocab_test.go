package posturevocab

import (
	"encoding/json"
	"strings"
	"testing"
)

// The two vocabularies must never share a word: KindOf decides whether a row
// is mirrored to the controller or served to agents, and a word in both would
// be sent to both.
func TestTheVocabulariesDoNotOverlap(t *testing.T) {
	for _, c := range AgentChecks() {
		if _, ok := ZitiTypeID(c.Type); ok {
			t.Errorf("%s is both an agent check and a Ziti posture check", c.Type)
		}
		if KindOf(c.Type) != KindAgent {
			t.Errorf("KindOf(%q) = %q, want agent", c.Type, KindOf(c.Type))
		}
	}
	for _, z := range ZitiTypes() {
		if KindOf(z) != KindZiti {
			t.Errorf("KindOf(%q) = %q, want ziti", z, KindOf(z))
		}
	}
	for _, unknown := range []string{"", "EDR", "OS_VERSION", "Disk_Encryption", "os", "PROCESS_MULTI"} {
		if k := KindOf(unknown); k != "" {
			t.Errorf("KindOf(%q) = %q, want neither", unknown, k)
		}
	}
}

// The console's spellings of the Ziti types map to the controller's typeIds,
// and the controller's own ids are accepted as themselves.
func TestZitiTypeIDs(t *testing.T) {
	for in, want := range map[string]string{
		"OS": "OS", "Domain": "DOMAIN", "DOMAIN": "DOMAIN", "MFA": "MFA",
		"Process": "PROCESS", "PROCESS": "PROCESS", "MAC": "MAC",
	} {
		if got, ok := ZitiTypeID(in); !ok || got != want {
			t.Errorf("ZitiTypeID(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := ZitiTypeID("disk_encryption"); ok {
		t.Error("an agent check has a Ziti typeId")
	}
}

// Every platform an agent check names is one GET /agent/config can match, and
// every check can run somewhere.
func TestEveryAgentCheckRunsOnAKnownPlatform(t *testing.T) {
	for _, c := range AgentChecks() {
		if len(c.Platforms) == 0 {
			t.Errorf("%s runs on no platform", c.Type)
		}
		for _, p := range c.Platforms {
			if !contains(Platforms(), p) {
				t.Errorf("%s names platform %q, which no enrolled agent reports", c.Type, p)
			}
		}
		for _, p := range c.Params {
			if err := validateParam(p, sampleValue(p)); err != nil {
				t.Errorf("%s.%s: a valid sample was refused: %v", c.Type, p.Name, err)
			}
		}
	}
}

func sampleValue(p Param) interface{} {
	switch p.Kind {
	case ParamVersion:
		return "10.0.19045"
	case ParamInteger:
		return float64(p.Min)
	case ParamBoolean:
		return true
	case ParamStringList:
		return []interface{}{"MsMpEng.exe"}
	}
	return nil
}

// The result of AgentChecks is a copy: editing it does not change what the
// server accepts.
func TestAgentChecksReturnsACopy(t *testing.T) {
	got := AgentChecks()
	for i := range got {
		if got[i].Type == "process_running" {
			got[i].Platforms[0] = PlatformWindows
			got[i].Params[0].Required = false
		}
	}
	if err := ValidateAgentCheck("p", "process_running", map[string]interface{}{}, "high", nil); err == nil || err.Code != CodeMissingParam {
		t.Errorf("editing the returned params changed validation: %v", err)
	}
	if err := ValidateAgentCheck("p", "process_running", procs("sshd"), "high", []string{PlatformWindows}); err == nil {
		t.Error("editing the returned platforms let process_running be scoped to windows")
	}
}

func procs(names ...string) map[string]interface{} {
	list := make([]interface{}, len(names))
	for i, n := range names {
		list[i] = n
	}
	return map[string]interface{}{"processes": list}
}

// params decodes a JSON object the way gin's binder does, so the tests see
// the same float64s and []interface{} a request produces.
func params(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("fixture %s: %v", raw, err)
	}
	return m
}

func TestValidateAgentCheck(t *testing.T) {
	for _, tc := range []struct {
		name      string
		checkName string
		checkType string
		params    string
		severity  string
		platforms []string
		code      string // "" means valid
		field     string
	}{
		{name: "os_version with a minimum", checkType: "os_version", params: `{"min_version":"10.0.19045"}`,
			severity: "high", platforms: []string{"windows"}},
		{name: "os_version with no params", checkType: "os_version", params: `{}`, severity: "low"},
		{name: "null params mean none", checkType: "firewall", params: `null`, severity: "medium"},
		{name: "patch_level in range", checkType: "patch_level", params: `{"max_days":14}`, severity: "critical",
			platforms: []string{"windows", "macos"}},
		{name: "process_running with names", checkType: "process_running",
			params: `{"processes":["sshd","auditd"]}`, severity: "high", platforms: []string{"linux"}},
		{name: "play_integrity policy", checkType: "play_integrity",
			params: `{"require_meets_device_integrity":true,"require_play_recognized":false}`, severity: "critical",
			platforms: []string{"android"}},
		{name: "the any marker", checkType: "disk_encryption", params: `{}`, severity: "critical",
			platforms: []string{"any"}},

		{name: "a Ziti type", checkType: "OS", params: `{}`, severity: "high",
			code: CodeUnknownCheckType, field: "check_type"},
		{name: "an invented type", checkType: "jailbreak_root", params: `{}`, severity: "high",
			code: CodeUnknownCheckType, field: "check_type"},
		{name: "no name", checkName: " ", checkType: "firewall", params: `{}`, severity: "high",
			code: CodeInvalidName, field: "name"},
		{name: "a name too long for the column", checkName: strings.Repeat("n", 256), checkType: "firewall",
			params: `{}`, severity: "high", code: CodeInvalidName, field: "name"},
		{name: "no severity", checkType: "firewall", params: `{}`, severity: "",
			code: CodeInvalidSeverity, field: "severity"},
		{name: "a severity the scorer does not know", checkType: "firewall", params: `{}`, severity: "info",
			code: CodeInvalidSeverity, field: "severity"},
		{name: "a capitalised severity", checkType: "firewall", params: `{}`, severity: "High",
			code: CodeInvalidSeverity, field: "severity"},
		{name: "a platform spelt as GOOS", checkType: "firewall", params: `{}`, severity: "high",
			platforms: []string{"darwin"}, code: CodeInvalidPlatform, field: "platforms"},
		{name: "a capitalised platform", checkType: "firewall", params: `{}`, severity: "high",
			platforms: []string{"Windows"}, code: CodeInvalidPlatform, field: "platforms"},
		{name: "process_running on windows, where it declines", checkType: "process_running",
			params: `{"processes":["MsMpEng.exe"]}`, severity: "high", platforms: []string{"windows"},
			code: CodePlatformNotSupported, field: "platforms"},
		{name: "play_integrity on ios", checkType: "play_integrity", params: `{}`, severity: "high",
			platforms: []string{"android", "ios"}, code: CodePlatformNotSupported, field: "platforms"},
		{name: "a param the check does not read", checkType: "os_version", params: `{"os_type":"Windows"}`,
			severity: "high", code: CodeUnknownParam, field: "parameters.os_type"},
		{name: "a param on a check that takes none", checkType: "firewall", params: `{"require_enabled":true}`,
			severity: "high", code: CodeUnknownParam, field: "parameters.require_enabled"},
		{name: "a version with a prefix the agent cannot compare", checkType: "agent_version",
			params: `{"min_version":"v1.2.3"}`, severity: "high", code: CodeInvalidParam, field: "parameters.min_version"},
		{name: "a version as a number", checkType: "os_version", params: `{"min_version":10}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.min_version"},
		{name: "max_days as a string", checkType: "patch_level", params: `{"max_days":"30"}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.max_days"},
		{name: "max_days fractional", checkType: "patch_level", params: `{"max_days":7.5}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.max_days"},
		{name: "max_days zero", checkType: "patch_level", params: `{"max_days":0}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.max_days"},
		{name: "process_running with nothing to look for", checkType: "process_running", params: `{}`,
			severity: "high", code: CodeMissingParam, field: "parameters.processes"},
		{name: "process_running with an empty list", checkType: "process_running", params: `{"processes":[]}`,
			severity: "high", code: CodeMissingParam, field: "parameters.processes"},
		{name: "processes as one string", checkType: "process_running", params: `{"processes":"sshd"}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.processes"},
		{name: "a blank process name", checkType: "process_running", params: `{"processes":["sshd"," "]}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.processes"},
		{name: "a process name that is not a string", checkType: "process_running", params: `{"processes":[1]}`,
			severity: "high", code: CodeInvalidParam, field: "parameters.processes"},
		{name: "a play_integrity flag as a string", checkType: "play_integrity",
			params: `{"require_play_recognized":"yes"}`, severity: "high",
			code: CodeInvalidParam, field: "parameters.require_play_recognized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.checkName
			if name == "" {
				name = "a check"
			}
			err := ValidateAgentCheck(name, tc.checkType, params(t, tc.params), tc.severity, tc.platforms)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused a valid check: %s (%s): %s", err.Code, err.Field, err.Message)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted; want %s on %s", tc.code, tc.field)
			}
			if err.Code != tc.code || err.Field != tc.field {
				t.Fatalf("got %s on %s (%s); want %s on %s", err.Code, err.Field, err.Message, tc.code, tc.field)
			}
			if err.Message == "" {
				t.Fatal("an error with no message")
			}
		})
	}
}

// A long process list is refused before it reaches every agent's config.
func TestAStringListIsBounded(t *testing.T) {
	names := make([]string, 65)
	for i := range names {
		names[i] = "p"
	}
	if err := ValidateAgentCheck("p", "process_running", procs(names...), "high", nil); err == nil || err.Code != CodeInvalidParam {
		t.Fatalf("65 processes: %v, want invalid_param", err)
	}
	if err := ValidateAgentCheck("p", "process_running", procs(strings.Repeat("x", 257)), "high", nil); err == nil || err.Code != CodeInvalidParam {
		t.Fatalf("a 257-character process name: %v, want invalid_param", err)
	}
}
