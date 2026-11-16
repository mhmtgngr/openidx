package diagnose

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 16, 14, 5, 0, 0, time.UTC)

const agentGolden = "../../agent/internal/doctor/testdata/bundle_v1.json"

// The agent writes this file from its own types; decoding it strictly and
// writing it back unchanged proves the two copies of the schema agree.
func TestBundleMatchesTheAgentsWireFormat(t *testing.T) {
	raw, err := os.ReadFile(agentGolden)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("the agent's bundle does not parse: %v", err)
	}
	back, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(back, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a field is lost or changed on the way through the server's types:\nagent:  %s\nserver: %s", raw, back)
	}
}

// Every code the agent's doctor can report is either mapped to a cause or
// listed here as carrying no cause of its own.
func TestEveryDoctorCodeIsAccountedFor(t *testing.T) {
	src, err := os.ReadFile("../../agent/internal/doctor/bundle.go")
	if err != nil {
		t.Fatal(err)
	}
	notACause := map[string]bool{
		"CONFIG_UNREADABLE": true, // the doctor could not look; says nothing about the device
		"IDENTITY_EXPIRING": true, // a warning, not a failure
		"TUNNEL_OFF":        true, // a warning: the organization may not use the tunnel
		"INTERNAL":          true, // a check broke; not a reason the device cannot connect
	}
	codes := regexp.MustCompile(`Code\w+\s+= "([A-Z_]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(codes) < 20 {
		t.Fatalf("found only %d doctor codes; the pattern no longer matches", len(codes))
	}
	for _, m := range codes {
		if _, ok := bundleCauses[m[1]]; !ok && !notACause[m[1]] {
			t.Errorf("doctor code %s maps to no cause", m[1])
		}
	}
	for code, cause := range bundleCauses {
		if _, ok := catalog[cause]; !ok {
			t.Errorf("%s maps to %s, which is not in the catalog", code, cause)
		}
	}
}

func TestCatalogIsComplete(t *testing.T) {
	ranks := map[int]string{}
	for code, spec := range catalog {
		if len(spec.fixes) == 0 {
			t.Errorf("%s has no fix", code)
		}
		if other, dup := ranks[spec.rank]; dup {
			t.Errorf("%s and %s share rank %d: their order would be arbitrary", code, other, spec.rank)
		}
		ranks[spec.rank] = code
		for _, f := range spec.fixes {
			if f.Tier != TierUser && f.Tier != TierSafeFix && f.Tier != TierApproval {
				t.Errorf("%s: fix %s has tier %q", code, f.Action, f.Tier)
			}
		}
	}
	// Nothing that changes access, policy or the network may run unasked.
	for _, action := range []string{FixRequestAccess, FixApproveDevice, FixReinstateDevice, FixServiceHosting, FixServicePolicy} {
		for code, spec := range catalog {
			for _, f := range spec.fixes {
				if f.Action == action && f.Tier != TierApproval {
					t.Errorf("%s: %s must need approval", code, action)
				}
			}
		}
	}
	if all := AllCauses(); len(all) != len(catalog) || all[0] != CauseDeviceRevoked || all[len(all)-1] != CauseUnknown {
		t.Errorf("AllCauses = %v", all)
	}
}

func bundle(codes ...string) *Bundle {
	b := &Bundle{Schema: BundleSchema, CollectedAt: now.Add(-time.Minute)}
	for _, c := range codes {
		b.Checks = append(b.Checks, Check{ID: "x", Status: StatusFail, Code: c})
	}
	return b
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

func active() *DeviceFacts { return &DeviceFacts{Status: DeviceActive, Live: true, Compliant: yes()} }

func TestEvaluate(t *testing.T) {
	ok := &AccessFacts{Assigned: true}
	svc := &ServiceFacts{Exists: true, HasTerminator: true, DialAllowed: true}
	offline := &DeviceFacts{Status: DeviceActive, Compliant: yes()}
	cases := []struct {
		name    string
		ev      Evidence
		want    []string
		healthy bool
	}{
		{"all clean with a bundle", Evidence{Bundle: bundle(), Device: active(), Access: ok, Service: svc}, nil, true},
		{"clean and live without a bundle", Evidence{Device: active(), Access: ok}, nil, true},
		{"no evidence at all", Evidence{}, []string{CauseNoDevice}, false},
		{"nothing visible is not healthy", Evidence{Device: &DeviceFacts{Status: "odd"}}, []string{CauseUnknown}, false},
		{"device offline", Evidence{Device: offline, Access: ok}, []string{CauseDeviceOffline}, false},
		{"a fresh bundle means not offline", Evidence{Device: offline, Bundle: bundle("TUNNEL_DOWN")}, []string{CauseTunnelDown}, false},
		{"revoked outranks everything", Evidence{Device: &DeviceFacts{Status: DeviceRevoked}, Bundle: bundle("DNS_FAIL", "TUNNEL_DOWN"), Access: &AccessFacts{}},
			[]string{CauseDeviceRevoked, CauseDNSFail, CauseTunnelDown, CauseNotAssigned}, false},
		{"server and device agree on revoked once", Evidence{Device: &DeviceFacts{Status: DeviceRevoked}, Bundle: bundle("DEVICE_REVOKED")}, []string{CauseDeviceRevoked}, false},
		{"suspended", Evidence{Device: &DeviceFacts{Status: DeviceSuspended}}, []string{CauseDeviceSuspended}, false},
		{"pending approval", Evidence{Device: &DeviceFacts{Status: DevicePending}}, []string{CauseDevicePending}, false},
		{"unenrolled device says so itself", Evidence{Bundle: bundle("NOT_ENROLLED")}, []string{CauseNotEnrolled}, false},
		{"network before tunnel", Evidence{Device: active(), Bundle: bundle("TUNNEL_DOWN", "TCP_TIMEOUT", "CLOCK_SKEW")},
			[]string{CauseClockSkew, CauseNetworkBlocked, CauseTunnelDown}, false},
		{"two codes, one cause", Evidence{Device: active(), Bundle: bundle("DNS_FAIL", "DNS_TIMEOUT")}, []string{CauseDNSFail}, false},
		{"captive portal or inspection", Evidence{Device: active(), Bundle: bundle("TLS_UNTRUSTED")}, []string{CauseTLSIntercepted}, false},
		{"tunnel state from the last report", Evidence{Device: &DeviceFacts{Status: DeviceActive, Live: true, TunnelState: "degraded"}}, []string{CauseTunnelDown}, false},
		{"outdated agent", Evidence{Device: &DeviceFacts{Status: DeviceActive, Live: true, Outdated: true}}, []string{CauseAgentOutdated}, false},
		{"posture where trust is required", Evidence{Device: &DeviceFacts{Status: DeviceActive, Live: true, Compliant: no()}, Access: &AccessFacts{Assigned: true, DeviceTrustRequired: true}, Service: &ServiceFacts{Exists: true, HasTerminator: true}},
			[]string{CausePostureFail}, false},
		{"posture where trust is not required", Evidence{Device: &DeviceFacts{Status: DeviceActive, Live: true, Compliant: no()}, Access: ok}, nil, true},
		{"not assigned hides the service's own faults", Evidence{Device: active(), Access: &AccessFacts{}, Service: &ServiceFacts{}}, []string{CauseNotAssigned}, false},
		{"step-up", Evidence{Device: active(), Access: &AccessFacts{Assigned: true, StepUpRequired: true}}, []string{CauseStepUpRequired}, false},
		{"no terminator", Evidence{Device: active(), Access: ok, Service: &ServiceFacts{Exists: true}}, []string{CauseServiceNoTerminator}, false},
		{"policy gap", Evidence{Device: active(), Access: ok, Service: &ServiceFacts{Exists: true, HasTerminator: true}}, []string{CausePolicyGap}, false},
		{"refused credential", Evidence{Device: &DeviceFacts{Status: DeviceActive, CredentialRefused: true}}, []string{CauseAuthInvalid, CauseDeviceOffline}, false},
		{"unknown doctor code is ignored, not fatal", Evidence{Device: active(), Bundle: bundle("SOMETHING_NEW")}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ev.Now = now
			v := Evaluate(tc.ev)
			var got []string
			for _, c := range v.Causes {
				got = append(got, c.Code)
				if len(c.Fixes) == 0 || (c.Source != "device" && c.Source != "server") {
					t.Errorf("cause %+v lacks fixes or a source", c)
				}
			}
			if !reflect.DeepEqual(got, tc.want) || v.Healthy != tc.healthy {
				t.Errorf("causes = %v healthy = %v, want %v / %v", got, v.Healthy, tc.want, tc.healthy)
			}
			if v.Healthy && v.Causes == nil {
				t.Error("a healthy verdict must carry an empty list, not null")
			}
		})
	}
}

func TestAStaleBundleIsNotUsed(t *testing.T) {
	old := bundle("TUNNEL_DOWN")
	old.CollectedAt = now.Add(-time.Hour)
	v := Evaluate(Evidence{Now: now, Bundle: old, Device: &DeviceFacts{Status: DeviceActive, Compliant: yes()}})
	if !v.BundleStale || v.Primary() != CauseDeviceOffline {
		t.Errorf("verdict = %+v", v)
	}
}

func TestParseBundleBoundsWhatADeviceSends(t *testing.T) {
	good := func(mutate func(m map[string]any)) []byte {
		m := map[string]any{
			"schema": 1, "agent_version": "0.6.0", "os": "linux", "collected_at": "2026-11-16T14:02:00Z",
			"checks":  []any{map[string]any{"id": "dns", "status": "fail", "code": "DNS_FAIL", "ms": 1}},
			"repairs": []any{}, "enrollment": map[string]any{"enrolled": true, "auth_invalid": false, "revoked": false},
			"net": map[string]any{"proxy_mode": "none", "dns_ok": false},
		}
		if mutate != nil {
			mutate(m)
		}
		raw, _ := json.Marshal(m)
		return raw
	}
	if b, err := ParseBundle(good(nil)); err != nil || !b.failed("DNS_FAIL") {
		t.Fatalf("a good bundle was refused: %v", err)
	}
	many := make([]any, maxChecks+1)
	for i := range many {
		many[i] = map[string]any{"id": "x", "status": "pass", "ms": 0}
	}
	bad := map[string][]byte{
		"wrong schema":   good(func(m map[string]any) { m["schema"] = 2 }),
		"unknown field":  good(func(m map[string]any) { m["auth_token"] = "x" }),
		"unknown status": good(func(m map[string]any) { m["checks"] = []any{map[string]any{"id": "x", "status": "great", "ms": 0}} }),
		"too many":       good(func(m map[string]any) { m["checks"] = many }),
		"too large":      good(func(m map[string]any) { m["os"] = strings.Repeat("a", MaxBundleBytes) }),
		"trailing data":  append(good(nil), []byte(`{"schema":1}`)...),
		"not json":       []byte("hello"),
	}
	for name, raw := range bad {
		if _, err := ParseBundle(raw); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: err = %v, want ErrBundle", name, err)
		}
	}
	long := good(func(m map[string]any) {
		m["checks"] = []any{map[string]any{"id": "tunnel", "status": "fail", "code": "TUNNEL_DOWN", "detail": strings.Repeat("ş", 5000), "ms": 1}}
	})
	b, err := ParseBundle(long)
	if err != nil || len([]rune(b.Checks[0].Detail)) != maxText {
		t.Errorf("device text was not clipped: %v", err)
	}
}

// The agent writes this file from its own encoder; every code in it must
// decode here to the same list.
func TestSupportCodesFromTheAgentDecode(t *testing.T) {
	raw, err := os.ReadFile("../../agent/internal/doctor/testdata/support_codes.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string][]string
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) < 4 {
		t.Fatalf("only %d golden support codes", len(golden))
	}
	for code, want := range golden {
		got, err := DecodeSupportCode(code)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s decodes to %v (%v), the agent meant %v", code, got, err, want)
		}
		if got, err := DecodeSupportCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s as spoken: %v (%v)", code, got, err)
		}
	}
	for _, bad := range []string{"", "hello", "OX1-", "OX1-0000", strings.Repeat("A", 500)} {
		if _, err := DecodeSupportCode(bad); !errors.Is(err, ErrSupportCode) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	v := Evaluate(Evidence{Bundle: BundleFromCodes([]string{"TUNNEL_DOWN"}), Device: &DeviceFacts{Status: DeviceActive}})
	if v.Primary() != CauseTunnelDown {
		t.Errorf("verdict from a support code = %+v", v)
	}
}

// Every cause has words in every console locale. The console falls back to
// UNKNOWN for a code it has no words for, so a missing one would not break a
// page; it would tell someone "we could not tell" when the server could.
func TestEveryCauseHasWordsInTheConsole(t *testing.T) {
	for _, locale := range []string{"en", "tr"} {
		src, err := os.ReadFile("../../web/admin-console/src/i18n/locales/" + locale + ".ts")
		if err != nil {
			t.Fatal(err)
		}
		_, after, found := strings.Cut(string(src), "  diagnose: {")
		if !found {
			t.Fatalf("%s has no diagnose block", locale)
		}
		block, _, _ := strings.Cut(after, "\n  },\n")
		for _, code := range AllCauses() {
			entry := regexp.MustCompile(`(?s)\n      ` + code + `: \{\s+title: '.+?',\s+action: '.+?',\s+\},`)
			if !entry.MatchString(block) {
				t.Errorf("%s.ts has no title and action for %s", locale, code)
			}
		}
	}
}
