package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The posture round trip, driven through both handlers against a database, in
// the shapes the two shipped agents actually put on the wire. See
// agent_posture_wire_test.go for why the shapes differ.

// postureWireSchema is the slice of the fleet tables these handlers read and
// write. agent_posture_results follows migration v43's column types, so a
// status that would not fit the real table does not fit this one either.
var postureWireSchema = []string{
	`CREATE TABLE known_devices (
		id UUID PRIMARY KEY, org_id UUID, trusted BOOLEAN DEFAULT false)`,
	`CREATE TABLE enrolled_agents (
		agent_id          VARCHAR(64) PRIMARY KEY,
		org_id            UUID NOT NULL,
		auth_token_hash   VARCHAR(128) NOT NULL,
		status            VARCHAR(20) NOT NULL DEFAULT 'active',
		platform          VARCHAR(32),
		known_device_id   UUID,
		compliance_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
		compliance_score  DOUBLE PRECISION DEFAULT 0.0,
		last_seen_at      TIMESTAMPTZ,
		last_report_at    TIMESTAMPTZ,
		-- the device key columns migration v227 adds: the report path reads
		-- them to decide whether a signature is due, and against a table
		-- without them every report is answered with a 500
		device_public_key TEXT,
		device_key_kind   VARCHAR(16))`,
	`CREATE TABLE posture_checks (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		check_type VARCHAR(100) NOT NULL,
		parameters JSONB DEFAULT '{}',
		enabled    BOOLEAN DEFAULT true,
		severity   VARCHAR(50) DEFAULT 'medium',
		platforms  JSONB)`,
	`CREATE TABLE agent_posture_results (
		id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		agent_id           VARCHAR(64) NOT NULL,
		check_type         VARCHAR(64) NOT NULL,
		status             VARCHAR(10) NOT NULL,
		score              FLOAT DEFAULT 0.0,
		severity           VARCHAR(10) NOT NULL,
		details            JSONB DEFAULT '{}',
		message            TEXT,
		reported_at        TIMESTAMPTZ DEFAULT NOW(),
		expires_at         TIMESTAMPTZ,
		enforced           BOOLEAN DEFAULT FALSE,
		enforcement_action VARCHAR(20),
		org_id             UUID)`,
}

func setupPostureWireDB(t *testing.T, seeds ...string) (*AgentAPIHandler, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	ctx := context.Background()
	for _, stmt := range append(append([]string{}, postureWireSchema...), seeds...) {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			cleanup()
			t.Fatalf("setup: %v\n%s", err, stmt)
		}
	}
	gin.SetMode(gin.TestMode)
	return NewAgentAPIHandler(zap.NewNop(), db, nil, nil), cleanup
}

func seedAgent(agentID, status, platform string) string {
	return `INSERT INTO enrolled_agents (agent_id, org_id, auth_token_hash, status, platform) VALUES ('` +
		agentID + `','` + devOrg + `','` + sha256Hex("secret-"+agentID) + `','` + status + `','` + platform + `')`
}

// getAgentConfig drives GET /agent/config with the agent's own credential and
// returns the raw body.
func getAgentConfig(t *testing.T, h *AgentAPIHandler, agentID string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	c.Request.Header.Set("X-Agent-ID", agentID)
	c.Request.Header.Set("X-Auth-Token", "secret-"+agentID)
	h.HandleConfig(c)
	if w.Code != http.StatusOK {
		t.Fatalf("config for %s: %d %s", agentID, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

func TestAgentConfig_TheGoAgentGetsTypeAndParams(t *testing.T) {
	h, cleanup := setupPostureWireDB(t,
		seedAgent("go-agent", "active", "windows"),
		seedAgent("waiting-agent", "pending", "windows"),
		`INSERT INTO posture_checks (check_type, severity, parameters) VALUES
			('os_version',      'high',   '{"min_version": "10.0.19045"}'),
			('process_running', 'medium', '{"processes": ["MsMpEng.exe"]}'),
			('firewall',        'medium', NULL),
			('antivirus',       'low',    '{}'),
			('screen_lock',     'low',    '["not", "an", "object"]')`,
		`INSERT INTO posture_checks (check_type, severity, parameters, enabled) VALUES
			('disk_encryption', 'critical', '{"x": 1}', false)`,
	)
	defer cleanup()

	body := getAgentConfig(t, h, "go-agent")

	// Decode with the Go agent's own field set (agent/internal/checks
	// CheckConfig). A non-object params value would fail this decode for the
	// whole config, which is what the agent itself would do with it.
	var goAgent struct {
		Checks []struct {
			Type     string                 `json:"type"`
			Params   map[string]interface{} `json:"params,omitempty"`
			Severity string                 `json:"severity"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(body, &goAgent); err != nil {
		t.Fatalf("the Go agent could not decode its config: %v\n%s", err, body)
	}
	byType := map[string]map[string]interface{}{}
	var types []string
	for _, c := range goAgent.Checks {
		if c.Type == "" {
			t.Errorf("a check reached the Go agent with no type: %s", body)
		}
		byType[c.Type] = c.Params
		types = append(types, c.Type)
	}
	sort.Strings(types)
	want := []string{"antivirus", "firewall", "os_version", "process_running", "screen_lock"}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("types = %v, want %v (a disabled check stays out)", types, want)
	}
	if got := byType["os_version"]["min_version"]; got != "10.0.19045" {
		t.Errorf("os_version params.min_version = %v, want the stored 10.0.19045", got)
	}
	if got := byType["process_running"]["processes"]; !reflect.DeepEqual(got, []interface{}{"MsMpEng.exe"}) {
		t.Errorf("process_running params.processes = %v", got)
	}

	// On the wire: the Android agent's keys are still there and agree with
	// type, and params is absent wherever the row held no non-empty object.
	var wire struct {
		Checks []map[string]json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range wire.Checks {
		var typ, checkType, name string
		_ = json.Unmarshal(c["type"], &typ)
		_ = json.Unmarshal(c["check_type"], &checkType)
		_ = json.Unmarshal(c["name"], &name)
		if checkType != typ || name != typ {
			t.Errorf("type=%q check_type=%q name=%q; the Android agent reads check_type and name", typ, checkType, name)
		}
		_, hasParams := c["params"]
		switch typ {
		case "os_version", "process_running":
			if !hasParams {
				t.Errorf("%s was sent without its params", typ)
			}
		default:
			if hasParams {
				t.Errorf("%s was sent params %s from a row that holds no non-empty object", typ, c["params"])
			}
		}
	}

	// The pending baseline is a check the Go agent has to be able to run too.
	var pending struct {
		Checks []struct {
			Type string `json:"type"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(getAgentConfig(t, h, "waiting-agent"), &pending); err != nil {
		t.Fatalf("decode pending config: %v", err)
	}
	if len(pending.Checks) != 1 || pending.Checks[0].Type != "os_version" {
		t.Errorf("pending config checks = %+v, want one os_version with its type", pending.Checks)
	}
}

// goAgentResult is agent/internal/agent/agent.go engineResult, field for
// field: the Go agent is its own module, so its type cannot be imported here.
type goAgentResult struct {
	CheckType   string                 `json:"check_type"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"`
	Score       float64                `json:"score"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RanAt       time.Time              `json:"ran_at"`
}

func goAgentReport(t *testing.T, agentID string, results ...goAgentResult) string {
	t.Helper()
	body, err := json.Marshal(struct {
		AgentID    string          `json:"agent_id"`
		DeviceID   string          `json:"device_id"`
		Results    []goAgentResult `json:"results"`
		ReportedAt time.Time       `json:"reported_at"`
	}{agentID, "device-" + agentID, results, time.Now().UTC()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

func TestAgentReport_TheGoAgentsFlatResultsAreScored(t *testing.T) {
	h, cleanup := setupPostureWireDB(t,
		seedAgent("go-agent", "active", "windows"),
		seedAgent("android-agent", "active", "android"),
	)
	defer cleanup()
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	db := h.db

	report := func(t *testing.T, agentID, body string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `DELETE FROM agent_posture_results`); err != nil {
			t.Fatalf("reset results: %v", err)
		}
		if w := postAgentReport(h, agentID, "secret-"+agentID, body); w.Code != http.StatusAccepted {
			t.Fatalf("report: %d %s", w.Code, w.Body.String())
		}
	}
	type row struct {
		status, message, action string
		score                   float64
		details                 map[string]interface{}
	}
	stored := func(t *testing.T, agentID, checkType string) row {
		t.Helper()
		var r row
		var details []byte
		if err := db.Pool.QueryRow(ctx, `
			SELECT status, score, COALESCE(message, ''), COALESCE(enforcement_action, ''), details
			  FROM agent_posture_results WHERE agent_id = $1 AND check_type = $2`,
			agentID, checkType).Scan(&r.status, &r.score, &r.message, &r.action, &details); err != nil {
			t.Fatalf("stored result for %s/%s: %v", agentID, checkType, err)
		}
		_ = json.Unmarshal(details, &r.details)
		return r
	}
	compliance := func(t *testing.T, agentID string) (string, float64) {
		t.Helper()
		var status string
		var score float64
		if err := db.Pool.QueryRow(ctx,
			`SELECT compliance_status, compliance_score FROM enrolled_agents WHERE agent_id = $1`,
			agentID).Scan(&status, &score); err != nil {
			t.Fatalf("compliance for %s: %v", agentID, err)
		}
		return status, score
	}
	ranAt := time.Date(2026, 10, 5, 10, 0, 0, 123456789, time.UTC)

	t.Run("a passing Go agent is compliant", func(t *testing.T) {
		report(t, "go-agent", goAgentReport(t, "go-agent",
			goAgentResult{CheckType: "os_version", Severity: "high", Status: "pass", Score: 1,
				Message: "OS: windows 10.0.19045 (amd64)", Details: map[string]interface{}{"version": "10.0.19045"}, RanAt: ranAt},
			goAgentResult{CheckType: "firewall", Severity: "medium", Status: "pass", Score: 1, RanAt: ranAt},
		))
		got := stored(t, "go-agent", "os_version")
		if got.status != "pass" || got.score != 1 {
			t.Errorf("os_version stored as status=%q score=%v, want pass/1", got.status, got.score)
		}
		if got.message != "OS: windows 10.0.19045 (amd64)" || got.details["version"] != "10.0.19045" {
			t.Errorf("os_version message=%q details=%v; the flat message and details were lost", got.message, got.details)
		}
		if fw := stored(t, "go-agent", "firewall"); fw.status != "pass" || fw.score != 1 {
			t.Errorf("firewall stored as status=%q score=%v, want pass/1", fw.status, fw.score)
		}
		if status, score := compliance(t, "go-agent"); status != "compliant" || score != 1 {
			t.Errorf("compliance = %s/%v, want compliant/1", status, score)
		}
	})

	t.Run("a Go agent failing a critical check is non-compliant", func(t *testing.T) {
		report(t, "go-agent", goAgentReport(t, "go-agent",
			goAgentResult{CheckType: "os_version", Severity: "high", Status: "pass", Score: 1, RanAt: ranAt},
			goAgentResult{CheckType: "disk_encryption", Severity: "critical", Status: "fail", Score: 0,
				Message: "BitLocker is off", Remediation: "Turn on BitLocker.", RanAt: ranAt},
		))
		got := stored(t, "go-agent", "disk_encryption")
		if got.status != "fail" || got.action != "revoke" || got.message != "BitLocker is off" {
			t.Errorf("disk_encryption stored as status=%q action=%q message=%q, want fail/revoke",
				got.status, got.action, got.message)
		}
		if status, _ := compliance(t, "go-agent"); status != "non_compliant" {
			t.Errorf("compliance = %s, want non_compliant", status)
		}
	})

	t.Run("the Android agent's nested report still works", func(t *testing.T) {
		report(t, "android-agent", `{"agent_id":"android-agent","device_id":"d","results":[
			{"check_type":"screen_lock","severity":"medium","ran_at":"2026-10-05T10:00:00Z",
			 "result":{"status":"pass","score":1.0,"message":"secure lock screen","details":{"secure":true}}}]}`)
		got := stored(t, "android-agent", "screen_lock")
		if got.status != "pass" || got.score != 1 || got.message != "secure lock screen" {
			t.Errorf("screen_lock stored as status=%q score=%v message=%q", got.status, got.score, got.message)
		}
		if status, _ := compliance(t, "android-agent"); status != "compliant" {
			t.Errorf("compliance = %s, want compliant", status)
		}
	})

	t.Run("a result with no status anywhere is not a pass", func(t *testing.T) {
		report(t, "go-agent", `{"results":[{"check_type":"firewall","severity":"low","score":1}]}`)
		if got := stored(t, "go-agent", "firewall"); got.status != "" || got.score != 0 {
			t.Errorf("firewall stored as status=%q score=%v from a result that reported none", got.status, got.score)
		}
		if status, _ := compliance(t, "go-agent"); status != "unknown" {
			t.Errorf("compliance = %s, want unknown: a bare score must not make a device compliant", status)
		}
	})
}
