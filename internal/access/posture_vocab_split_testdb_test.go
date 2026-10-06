package access

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ONE TABLE, TWO VOCABULARIES.
//
// posture_checks holds the Ziti posture checks the controller enforces and the
// device agent checks the OpenIDX agents run (internal/access/posturevocab).
// These tests drive both halves of the split: GET /agent/config serves agents
// only what they can run, and nothing an agent runs is ever written to the
// controller.

// configTypes decodes an agent config the way the Go agent reads it and
// returns the check types, sorted.
func configTypes(t *testing.T, body []byte) []string {
	t.Helper()
	var cfg struct {
		Checks []struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("decode config: %v\n%s", err, body)
	}
	out := make([]string, 0, len(cfg.Checks))
	for _, c := range cfg.Checks {
		out = append(out, c.Type)
	}
	sort.Strings(out)
	return out
}

// An agent is served the agent checks and none of the Ziti posture checks
// that share their table. Before the split it got every enabled row, and the
// Go agent answered OS, Domain and MFA with "unknown check type".
func TestAgentConfig_ServesOnlyTheAgentVocabulary(t *testing.T) {
	h, cleanup := setupPostureWireDB(t,
		seedAgent("win-agent", "active", "windows"),
		seedAgent("droid-agent", "active", "android"),
		`INSERT INTO posture_checks (check_type, severity, parameters, platforms) VALUES
			('OS',              'high',     '{"operating_systems":[{"type":"Windows"}]}', NULL),
			('Domain',          'high',     '{"domains":["corp.example"]}',               NULL),
			('MFA',             'medium',   '{}',                                         NULL),
			('PROCESS',         'medium',   '{}',                                         NULL),
			('EDR',             'critical', '{}',                                         NULL),
			('disk_encryption', 'critical', '{}',                                         NULL),
			('os_version',      'high',     '{"min_version":"10.0.19045"}',               '["windows"]'),
			('play_integrity',  'critical', '{"require_meets_device_integrity":true}',    '["android"]')`,
	)
	defer cleanup()

	if got, want := configTypes(t, getAgentConfig(t, h, "win-agent")), []string{"disk_encryption", "os_version"}; !reflect.DeepEqual(got, want) {
		t.Errorf("windows agent was served %v, want %v", got, want)
	}
	if got, want := configTypes(t, getAgentConfig(t, h, "droid-agent")), []string{"disk_encryption", "play_integrity"}; !reflect.DeepEqual(got, want) {
		t.Errorf("android agent was served %v, want %v", got, want)
	}
}

// With only Ziti posture checks configured, an agent has no check of its own
// and is given the defaults rather than an OS row it cannot run.
func TestAgentConfig_ZitiChecksAloneLeaveTheAgentOnItsDefaults(t *testing.T) {
	h, cleanup := setupPostureWireDB(t,
		seedAgent("win-agent", "active", "windows"),
		`INSERT INTO posture_checks (check_type, severity) VALUES ('OS', 'high'), ('MFA', 'critical')`,
	)
	defer cleanup()

	var want []string
	for _, c := range defaultAgentConfig().Checks {
		want = append(want, c.Type)
	}
	sort.Strings(want)
	if got := configTypes(t, getAgentConfig(t, h, "win-agent")); !reflect.DeepEqual(got, want) {
		t.Errorf("served %v, want the defaults %v", got, want)
	}
}

// postureCheckCalls is what the controller was asked about posture checks
// since resetCalls.
func (f *zitiScopeFixture) postureCheckCalls() []string {
	var out []string
	for _, c := range f.managementCalls() {
		if strings.Contains(c, "/posture-checks") {
			out = append(out, c)
		}
	}
	return out
}

// serveZitiPostureChecks lets the stub controller accept posture check writes.
func (f *zitiScopeFixture) serveZitiPostureChecks() {
	f.stub.on("POST /edge/management/v1/posture-checks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"zpc-` + f.sfx + `"}}`))
	})
	f.stub.ok("PUT /edge/management/v1/posture-checks/", `{"data":{}}`)
	f.stub.ok("DELETE /edge/management/v1/posture-checks/", `{"data":{}}`)
}

// createPostureCheck creates a posture check as cl and returns the id and
// kind it was answered with.
func (f *zitiScopeFixture) createPostureCheck(cl zitiCaller, body string) (id, kind string) {
	f.t.Helper()
	code, resp := f.do(cl, http.MethodPost, "/api/v1/access/ziti/posture/checks", body)
	if code != http.StatusCreated {
		f.t.Fatalf("create: %d %s, want 201", code, resp)
	}
	var out struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil || out.ID == "" {
		f.t.Fatalf("create answered %s (%v)", resp, err)
	}
	return out.ID, out.Kind
}

// A device agent check goes through the same endpoints the console has always
// used, and is created, listed, edited and deleted without one call to the
// controller. A Ziti posture check still reaches it.
func TestAgentChecksNeverReachTheController(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.serveZitiPostureChecks()
	admin, operator := f.caller("adminB", "admin"), f.caller("operatorB", "operator")
	const checks = "/api/v1/access/ziti/posture/checks"

	f.resetCalls()
	id, kind := f.createPostureCheck(admin,
		`{"name":"disk-`+f.sfx+`","check_type":"disk_encryption","severity":"critical","enabled":true,
		  "platforms":["windows","macos"],"parameters":{}}`)
	if kind != "agent" {
		t.Errorf("an agent check was answered with kind %q", kind)
	}
	if calls := f.postureCheckCalls(); len(calls) != 0 {
		t.Errorf("creating an agent check reached the controller: %v", calls)
	}
	if got := f.scalar(`SELECT COALESCE(ziti_id, 'NULL') || ' ' || org_id::text || ' ' || platforms::text
		FROM posture_checks WHERE id = $1`, id); got != `NULL `+f.orgB.ID+` ["windows", "macos"]` {
		t.Errorf("stored as %q", got)
	}

	// The two kinds list apart, and together when no kind is asked for.
	lists := map[string]struct{ agent, ziti bool }{
		checks + "?kind=agent": {true, false},
		checks + "?kind=ziti":  {false, true},
		checks:                 {true, true},
	}
	for path, want := range lists {
		code, body := f.do(operator, http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Errorf("GET %s: %d %s", path, code, body)
			continue
		}
		if got := strings.Contains(body, "disk-"+f.sfx); got != want.agent {
			t.Errorf("GET %s shows the agent check = %v, want %v: %s", path, got, want.agent, body)
		}
		if got := strings.Contains(body, "posture-b-"+f.sfx); got != want.ziti {
			t.Errorf("GET %s shows the Ziti check = %v, want %v: %s", path, got, want.ziti, body)
		}
	}
	if code, body := f.do(operator, http.MethodGet, checks+"?kind=both", ""); code != http.StatusBadRequest || !strings.Contains(body, "invalid_kind") {
		t.Errorf("GET ?kind=both: %d %s, want 400 invalid_kind", code, body)
	}

	f.resetCalls()
	if code, body := f.do(admin, http.MethodPut, checks+"/"+id,
		`{"name":"os-`+f.sfx+`","check_type":"os_version","severity":"high","enabled":false,
		  "parameters":{"min_version":"10.0.19045"}}`); code != http.StatusOK || !strings.Contains(body, `"kind":"agent"`) {
		t.Errorf("update an agent check: %d %s, want 200", code, body)
	}
	if got := f.scalar(`SELECT check_type || ' ' || severity || ' ' || enabled::text || ' ' || (parameters->>'min_version') || ' ' || COALESCE(platforms::text, 'NULL')
		FROM posture_checks WHERE id = $1`, id); got != "os_version high false 10.0.19045 NULL" {
		t.Errorf("after update: %q", got)
	}

	// Another organization's admin cannot see it to change it.
	for _, rq := range []struct{ method, body string }{
		{http.MethodPut, `{"name":"x","check_type":"firewall","severity":"low","parameters":{}}`},
		{http.MethodDelete, ""},
	} {
		if code, body := f.do(f.caller("adminA", "admin"), rq.method, checks+"/"+id, rq.body); code != http.StatusNotFound {
			t.Errorf("%s of B's agent check by A's admin: %d %s, want 404", rq.method, code, body)
		}
	}

	if code, body := f.do(admin, http.MethodDelete, checks+"/"+id, ""); code != http.StatusNoContent {
		t.Errorf("delete an agent check: %d %s, want 204", code, body)
	}
	if n := f.scalar(`SELECT COUNT(*)::text FROM posture_checks WHERE id = $1`, id); n != "0" {
		t.Errorf("the agent check is still stored")
	}
	if calls := f.postureCheckCalls(); len(calls) != 0 {
		t.Errorf("editing and deleting an agent check reached the controller: %v", calls)
	}

	// A Ziti posture check is still mirrored.
	f.resetCalls()
	zid, zkind := f.createPostureCheck(admin,
		`{"name":"os-ziti-`+f.sfx+`","check_type":"OS","severity":"high","enabled":true,
		  "parameters":{"operating_systems":[{"type":"Windows","versions":["10"]}]}}`)
	if zkind != "ziti" {
		t.Errorf("a Ziti check was answered with kind %q", zkind)
	}
	if !f.stub.saw("POST /edge/management/v1/posture-checks") {
		t.Errorf("creating a Ziti check did not reach the controller: %v", f.managementCalls())
	}

	// Neither kind turns into the other.
	for _, rq := range []struct{ id, body string }{
		{zid, `{"name":"x","check_type":"disk_encryption","severity":"high","parameters":{}}`},
	} {
		f.resetCalls()
		if code, body := f.do(admin, http.MethodPut, checks+"/"+rq.id, rq.body); code != http.StatusBadRequest || !strings.Contains(body, "check_kind_change") {
			t.Errorf("change a Ziti check into an agent check: %d %s, want 400 check_kind_change", code, body)
		}
		if calls := f.postureCheckCalls(); len(calls) != 0 {
			t.Errorf("a refused change of kind reached the controller: %v", calls)
		}
	}
	aid, _ := f.createPostureCheck(admin,
		`{"name":"fw-`+f.sfx+`","check_type":"firewall","severity":"medium","enabled":true,"parameters":{}}`)
	if code, body := f.do(admin, http.MethodPut, checks+"/"+aid,
		`{"name":"x","check_type":"OS","severity":"high","parameters":{}}`); code != http.StatusBadRequest || !strings.Contains(body, "check_kind_change") {
		t.Errorf("change an agent check into a Ziti check: %d %s, want 400 check_kind_change", code, body)
	}
}

// The controller path itself refuses an agent check, whoever calls it, so the
// guarantee does not rest on every handler remembering to branch.
func TestTheControllerPathRefusesAgentChecks(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.serveZitiPostureChecks()
	zm := f.svc.ziti()
	ctx := orgctx.With(f.ctx, f.orgB)

	f.resetCalls()
	err := zm.CreatePostureCheck(ctx, &PostureCheck{Name: "x", CheckType: "disk_encryption", Severity: "high"})
	if !errors.Is(err, errNotAZitiCheck) {
		t.Errorf("CreatePostureCheck(disk_encryption) = %v, want errNotAZitiCheck", err)
	}

	var agentID string
	if err := f.db.Pool.QueryRow(f.ctx, `INSERT INTO posture_checks (name, check_type, severity, org_id)
		VALUES ('agent-row', 'firewall', 'high', $1::uuid) RETURNING id::text`, f.orgB.ID).Scan(&agentID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Even named with a Ziti type, the stored row is an agent check and has
	// no controller object to update.
	err = zm.UpdatePostureCheck(ctx, agentID, &PostureCheck{Name: "x", CheckType: "OS", Severity: "high"})
	if !errors.Is(err, errNotAZitiCheck) {
		t.Errorf("UpdatePostureCheck of an agent row = %v, want errNotAZitiCheck", err)
	}
	if calls := f.postureCheckCalls(); len(calls) != 0 {
		t.Errorf("the controller was asked: %v", calls)
	}
	if got := f.scalar(`SELECT check_type FROM posture_checks WHERE id = $1`, agentID); got != "firewall" {
		t.Errorf("the agent row became %q", got)
	}
	// Deleting one through the controller path removes the row and asks the
	// controller nothing: it has no ziti_id to delete.
	if err := zm.DeletePostureCheck(ctx, agentID); err != nil {
		t.Errorf("DeletePostureCheck of an agent row: %v", err)
	}
	if calls := f.postureCheckCalls(); len(calls) != 0 {
		t.Errorf("the controller was asked: %v", calls)
	}
}

// A check the agents cannot run as written is refused with a code that says
// what is wrong, and nothing is stored.
func TestAgentChecksAreValidated(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.serveZitiPostureChecks()
	admin := f.caller("adminB", "admin")
	const checks = "/api/v1/access/ziti/posture/checks"
	before := f.scalar(`SELECT COUNT(*)::text FROM posture_checks`)

	for _, tc := range []struct{ name, body, code, field string }{
		{"a type in neither vocabulary", `{"name":"x","check_type":"jailbreak_root","severity":"high"}`,
			"unknown_check_type", "check_type"},
		{"no severity", `{"name":"x","check_type":"firewall"}`, "invalid_severity", "severity"},
		{"a severity nothing scores", `{"name":"x","check_type":"firewall","severity":"info"}`,
			"invalid_severity", "severity"},
		{"no name", `{"name":"","check_type":"firewall","severity":"high"}`, "invalid_name", "name"},
		{"a platform no agent reports", `{"name":"x","check_type":"firewall","severity":"high","platforms":["darwin"]}`,
			"invalid_platform", "platforms"},
		{"a platform the check cannot run on", `{"name":"x","check_type":"process_running","severity":"high",
			"platforms":["windows"],"parameters":{"processes":["MsMpEng.exe"]}}`, "platform_not_supported", "platforms"},
		{"a param the check does not read", `{"name":"x","check_type":"os_version","severity":"high",
			"parameters":{"os_type":"Windows","min_version":"10"}}`, "unknown_param", "parameters.os_type"},
		{"a param of the wrong type", `{"name":"x","check_type":"patch_level","severity":"high",
			"parameters":{"max_days":"30"}}`, "invalid_param", "parameters.max_days"},
		{"a version the agent cannot compare", `{"name":"x","check_type":"agent_version","severity":"high",
			"parameters":{"min_version":"v2"}}`, "invalid_param", "parameters.min_version"},
		{"a required param missing", `{"name":"x","check_type":"process_running","severity":"high"}`,
			"missing_param", "parameters.processes"},
	} {
		code, body := f.do(admin, http.MethodPost, checks, tc.body)
		var resp struct{ Error, Code, Field string }
		_ = json.Unmarshal([]byte(body), &resp)
		if code != http.StatusBadRequest || resp.Code != tc.code || resp.Field != tc.field || resp.Error == "" {
			t.Errorf("%s: %d %s, want 400 %s on %s", tc.name, code, body, tc.code, tc.field)
		}
	}
	if after := f.scalar(`SELECT COUNT(*)::text FROM posture_checks`); after != before {
		t.Errorf("refused creates stored rows: %s before, %s after", before, after)
	}

	// The same rules hold on update.
	id, _ := f.createPostureCheck(admin,
		`{"name":"patch-`+f.sfx+`","check_type":"patch_level","severity":"high","parameters":{"max_days":30}}`)
	code, body := f.do(admin, http.MethodPut, checks+"/"+id,
		`{"name":"patch","check_type":"patch_level","severity":"high","parameters":{"max_days":0}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, `"code":"invalid_param"`) {
		t.Errorf("update with max_days 0: %d %s, want 400 invalid_param", code, body)
	}
	if got := f.scalar(`SELECT parameters->>'max_days' FROM posture_checks WHERE id = $1`, id); got != "30" {
		t.Errorf("a refused update changed max_days to %s", got)
	}
	if code, body := f.do(admin, http.MethodPut, checks+"/not-a-uuid",
		`{"name":"patch","check_type":"patch_level","severity":"high"}`); code != http.StatusNotFound {
		t.Errorf("update of a malformed id: %d %s, want 404", code, body)
	}
}

// With no controller connected, agent checks can still be listed and written;
// a Ziti check still answers 503, as the Ziti page has always been told.
func TestAgentChecksNeedNoController(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.svc.SetZitiManager(nil)
	admin, operator := f.caller("adminB", "admin"), f.caller("operatorB", "operator")
	const checks = "/api/v1/access/ziti/posture/checks"

	id, _ := f.createPostureCheck(admin,
		`{"name":"lock-`+f.sfx+`","check_type":"screen_lock","severity":"high","enabled":true}`)
	if code, body := f.do(operator, http.MethodGet, checks+"?kind=agent", ""); code != http.StatusOK || !strings.Contains(body, "lock-"+f.sfx) {
		t.Errorf("list agent checks with no controller: %d %s", code, body)
	}
	if code, body := f.do(admin, http.MethodPut, checks+"/"+id,
		`{"name":"lock","check_type":"screen_lock","severity":"critical","enabled":true}`); code != http.StatusOK {
		t.Errorf("update with no controller: %d %s", code, body)
	}
	if code, body := f.do(operator, http.MethodGet, "/api/v1/access/ziti/posture/check-types", ""); code != http.StatusOK || !strings.Contains(body, `"process_running"`) {
		t.Errorf("the vocabulary with no controller: %d %s", code, body)
	}
	if code, body := f.do(admin, http.MethodDelete, checks+"/"+id, ""); code != http.StatusNoContent {
		t.Errorf("delete with no controller: %d %s", code, body)
	}

	if code, body := f.do(admin, http.MethodPost, checks,
		`{"name":"os","check_type":"OS","severity":"high"}`); code != http.StatusServiceUnavailable {
		t.Errorf("create a Ziti check with no controller: %d %s, want 503", code, body)
	}
	if code, body := f.do(operator, http.MethodGet, checks+"?kind=ziti", ""); code != http.StatusServiceUnavailable {
		t.Errorf("list Ziti checks with no controller: %d %s, want 503", code, body)
	}
}

// The vocabulary the console builds its forms from is the server's own.
func TestThePostureCheckVocabularyIsServed(t *testing.T) {
	f := newZitiScopeFixture(t)
	code, body := f.do(f.caller("operatorB", "operator"), http.MethodGet, "/api/v1/access/ziti/posture/check-types", "")
	if code != http.StatusOK {
		t.Fatalf("GET check-types: %d %s", code, body)
	}
	var v struct {
		Ziti  []string `json:"ziti"`
		Agent []struct {
			Type      string   `json:"type"`
			Platforms []string `json:"platforms"`
			Params    []struct {
				Name, Kind string
				Required   bool
			} `json:"params"`
		} `json:"agent"`
		Severities []string `json:"severities"`
		Platforms  []string `json:"platforms"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if !reflect.DeepEqual(v.Ziti, []string{"OS", "Domain", "MFA", "Process", "MAC"}) {
		t.Errorf("ziti = %v", v.Ziti)
	}
	if !reflect.DeepEqual(v.Severities, []string{"low", "medium", "high", "critical"}) {
		t.Errorf("severities = %v", v.Severities)
	}
	byType := map[string]int{}
	for i, c := range v.Agent {
		byType[c.Type] = i
	}
	pr, ok := byType["process_running"]
	if !ok || len(v.Agent[pr].Params) != 1 || v.Agent[pr].Params[0].Name != "processes" ||
		v.Agent[pr].Params[0].Kind != "string_list" || !v.Agent[pr].Params[0].Required {
		t.Errorf("process_running is described as %+v", v.Agent)
	}
	if code, body := f.do(f.caller("userB", "user"), http.MethodGet, "/api/v1/access/ziti/posture/check-types", ""); code != http.StatusForbidden {
		t.Errorf("a plain user read the vocabulary: %d %s", code, body)
	}
}

// The device health evaluator, behind the mobile self-report, judges the Ziti
// checks: a Domain check stored as the console spells it is evaluated rather
// than skipped as an unknown type, and an agent check is left to the agent
// rather than recorded as passed.
func TestDeviceHealthEvaluatesZitiChecksAndLeavesAgentChecksToTheAgent(t *testing.T) {
	f := newZitiScopeFixture(t)
	var domainID, agentID string
	if err := f.db.Pool.QueryRow(f.ctx, `INSERT INTO posture_checks (name, check_type, parameters, severity, org_id)
		VALUES ('domain', 'Domain', '{"domains":["corp.example"]}', 'high', $1::uuid) RETURNING id::text`,
		f.orgB.ID).Scan(&domainID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := f.db.Pool.QueryRow(f.ctx, `INSERT INTO posture_checks (name, check_type, severity, org_id)
		VALUES ('disk', 'disk_encryption', 'critical', $1::uuid) RETURNING id::text`,
		f.orgB.ID).Scan(&agentID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	code, body := f.do(f.caller("userB", "user"), http.MethodPost, "/api/v1/access/ziti/posture/device",
		`{"identity_id":"`+f.ziB+`","posture":{"os":"windows","os_version":"10.0","domain":"other.example"}}`)
	if code != http.StatusOK {
		t.Fatalf("self-report: %d %s", code, body)
	}
	var report DeviceHealthReport
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var sawDomain bool
	for _, c := range report.Checks {
		switch c.CheckType {
		case "Domain":
			sawDomain = true
			if c.Passed {
				t.Errorf("a device outside corp.example passed the Domain check: %+v", c)
			}
		case "disk_encryption":
			t.Errorf("the evaluator judged an agent check: %+v", c)
		}
	}
	if !sawDomain {
		t.Errorf("the Domain check was not evaluated: %s", body)
	}
	if n := f.scalar(`SELECT COUNT(*)::text FROM device_posture_results WHERE check_id = $1::uuid`, agentID); n != "0" {
		t.Errorf("%s results were recorded for the agent check", n)
	}
	if n := f.scalar(`SELECT COUNT(*)::text FROM device_posture_results WHERE check_id = $1::uuid AND NOT passed`, domainID); n != "1" {
		t.Errorf("the failed Domain check recorded %s failing results, want 1", n)
	}
}
