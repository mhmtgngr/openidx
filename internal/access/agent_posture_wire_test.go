package access

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The server and the Go agent did not speak the same posture wire format.
//
// GET /agent/config sent each check as check_type, and the Go agent dispatches
// on type (agent/internal/checks/registry.go CheckConfig), so every check ran
// there as "unknown check type". POST /agent/report read the outcome from a
// nested "result" object, and the Go agent sends it flat
// (agent/internal/agent/agent.go engineResult), so every Windows result was
// stored with an empty status and a score of 0. The Android agent uses
// check_type and the nested result and has to keep working unchanged.
//
// These are the pure halves of the fix. agent_posture_wire_testdb_test.go
// drives both handlers against a database.

func TestNormalizeCheckResult_ReadsBothAgentShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		// body is one element of the report's results array, as an agent
		// puts it on the wire.
		body        string
		wantStatus  string
		wantScore   float64
		wantMessage string
		wantRemedy  string
		wantDetails map[string]interface{}
		why         string
	}{
		{
			name: "nested only, as the Android agent sends it",
			body: `{"check_type":"screen_lock","severity":"medium",
				"result":{"status":"pass","score":1,"message":"locked","details":{"timeout":30}},
				"ran_at":"2026-10-05T10:00:00Z"}`,
			wantStatus: "pass", wantScore: 1, wantMessage: "locked",
			wantDetails: map[string]interface{}{"timeout": float64(30)},
			why:         "the Android shape must be read exactly as before",
		},
		{
			name: "flat only, as the Go agent sends it",
			body: `{"check_type":"os_version","severity":"high","status":"fail","score":0,
				"message":"OS version 10.0.17763 is below minimum required 10.0.19045",
				"remediation":"Upgrade the operating system to at least version 10.0.19045.",
				"details":{"version":"10.0.17763"},"ran_at":"2026-10-05T10:00:00.123456789Z"}`,
			wantStatus: "fail", wantScore: 0,
			wantMessage: "OS version 10.0.17763 is below minimum required 10.0.19045",
			wantRemedy:  "Upgrade the operating system to at least version 10.0.19045.",
			wantDetails: map[string]interface{}{"version": "10.0.17763"},
			why:         "this is the result the server used to read as an empty status",
		},
		{
			name: "flat pass keeps its score",
			body: `{"check_type":"firewall","severity":"medium","status":"pass","score":1,
				"ran_at":"2026-10-05T10:00:00Z"}`,
			wantStatus: "pass", wantScore: 1,
			why: "the score is what the compliance verdict is computed from",
		},
		{
			name: "both shapes, the nested result wins",
			body: `{"check_type":"disk_encryption","severity":"critical",
				"result":{"status":"pass","score":1,"message":"nested"},
				"status":"fail","score":0,"message":"flat","remediation":"flat"}`,
			wantStatus: "pass", wantScore: 1, wantMessage: "nested",
			why: "a present nested result is never overridden by top-level fields",
		},
		{
			name: "a nested result with no status gives way to a flat one",
			body: `{"check_type":"antivirus","severity":"high","result":{"score":1},
				"status":"fail","score":0,"message":"flat"}`,
			wantStatus: "fail", wantScore: 0, wantMessage: "flat",
			why: "a nested object without a status carries no outcome to prefer",
		},
		{
			name:       "neither shape",
			body:       `{"check_type":"firewall","severity":"low"}`,
			wantStatus: "", wantScore: 0,
			why: "nothing is invented for a result that reports nothing",
		},
		{
			name:       "a bare flat score with no status is not taken",
			body:       `{"check_type":"firewall","severity":"low","score":1,"message":"flat"}`,
			wantStatus: "", wantScore: 0,
			why: "a score without a status must not become a compliant result",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r checkResult
			if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := normalizeCheckResult(r).Result
			if got.Status != tc.wantStatus || got.Score != tc.wantScore {
				t.Errorf("status=%q score=%v, want status=%q score=%v (%s)",
					got.Status, got.Score, tc.wantStatus, tc.wantScore, tc.why)
			}
			if got.Message != tc.wantMessage {
				t.Errorf("message=%q, want %q", got.Message, tc.wantMessage)
			}
			if got.Remediation != tc.wantRemedy {
				t.Errorf("remediation=%q, want %q", got.Remediation, tc.wantRemedy)
			}
			if len(tc.wantDetails) > 0 && !reflect.DeepEqual(got.Details, tc.wantDetails) {
				t.Errorf("details=%v, want %v", got.Details, tc.wantDetails)
			}
		})
	}
}

func TestAgentCheckParams_SendsOnlyANonEmptyObject(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want string // "" means the params key is left out
	}{
		{"an object is passed through", []byte(`{"min_version": "10.0.19045"}`), `{"min_version": "10.0.19045"}`},
		{"a nested value survives", []byte(`{"processes": ["MsMpEng.exe"]}`), `{"processes": ["MsMpEng.exe"]}`},
		{"a NULL column", nil, ""},
		{"JSON null", []byte(`null`), ""},
		{"an empty object", []byte(`{}`), ""},
		{"an array would fail the Go agent's whole config decode", []byte(`["min_version"]`), ""},
		{"a scalar", []byte(`"strict"`), ""},
		{"malformed JSON", []byte(`{"min_version":`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := agentCheckParams(tc.raw)
			if string(got) != tc.want {
				t.Errorf("agentCheckParams(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// The fallback config is what an agent runs when the server has no posture
// checks for it, so a check sent there without a type is as dead as one sent
// from the database.
func TestDefaultAgentConfig_EveryCheckNamesItsType(t *testing.T) {
	body, err := json.Marshal(defaultAgentConfig())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var goAgent struct {
		Checks []struct {
			Type string `json:"type"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(body, &goAgent); err != nil {
		t.Fatalf("the Go agent could not decode the default config: %v", err)
	}
	cfg := defaultAgentConfig()
	if len(goAgent.Checks) != len(cfg.Checks) || len(cfg.Checks) == 0 {
		t.Fatalf("decoded %d checks from %d", len(goAgent.Checks), len(cfg.Checks))
	}
	for i, c := range goAgent.Checks {
		if c.Type == "" || c.Type != cfg.Checks[i].Name {
			t.Errorf("check %q reaches the Go agent with type %q", cfg.Checks[i].Name, c.Type)
		}
	}
}
