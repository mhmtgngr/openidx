package control

import (
	"encoding/json"
	"testing"

	"github.com/openidx/openidx/agent/internal/checks"
)

// The companion app drew a green "Compliant" badge on a phone nothing had
// examined.
//
// Engine.Posture() computed compliance as "nothing failed and nothing
// errored". Every check that has no implementation for the running operating
// system answers StatusWarn, and warns did not count — so on the gomobile
// builds (GOOS=android, GOOS=ios), where disk_encryption, screen_lock,
// patch_level, firewall, antivirus, domain_joined and integrity all fall to
// their platform fallback, the summary came out compliant on the strength of
// seven checks that never ran. disk_encryption is configured "critical".
//
// These cases drive the summariser directly with results shaped like each
// platform's, because the defect is in the arithmetic and a test that could
// only reproduce it on an Android handset would never run.

// summarise drives the production summariser. It deliberately does NOT
// reimplement it: a test that carries its own copy of the arithmetic passes
// while the code drifts, which is the inert-test shape this repository has
// spent its time deleting.
func summarise(t *testing.T, results []checks.EngineResult) posturePayload {
	t.Helper()
	return summarisePosture(results, "2026-01-01T00:00:00Z")
}

func res(checkType, severity string, status checks.Status, unsupported bool) checks.EngineResult {
	return checks.EngineResult{
		CheckType: checkType,
		Severity:  severity,
		Result:    &checks.CheckResult{Status: status, Unsupported: unsupported},
	}
}

func TestPostureComplianceRequiresHavingLooked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []checks.EngineResult
		want    bool
	}{
		{
			// The desktop case, unchanged: everything ran and passed.
			name: "a machine that was examined and passed is compliant",
			results: []checks.EngineResult{
				res("os_version", "high", checks.StatusPass, false),
				res("disk_encryption", "critical", checks.StatusPass, false),
				res("screen_lock", "high", checks.StatusPass, false),
			},
			want: true,
		},
		{
			// A real warn is still a measurement, and still does not deny
			// compliance — that behaviour is deliberate and unchanged.
			name: "a real warning does not deny compliance",
			results: []checks.EngineResult{
				res("os_version", "high", checks.StatusPass, false),
				res("firewall", "medium", checks.StatusWarn, false),
			},
			want: true,
		},
		{
			// THE DEFECT. Android's shape: one check runs, the rest cannot.
			name: "a phone whose critical checks could not run is NOT compliant",
			results: []checks.EngineResult{
				res("agent_version", "low", checks.StatusPass, false),
				res("disk_encryption", "critical", checks.StatusWarn, true),
				res("screen_lock", "high", checks.StatusWarn, true),
				res("patch_level", "high", checks.StatusWarn, true),
			},
			want: false,
		},
		{
			// A build with no checks at all cannot answer the question either.
			// "Nothing failed" is true of a device nobody looked at.
			name: "no checks at all is not compliance",
			results: []checks.EngineResult{
				res("disk_encryption", "critical", checks.StatusWarn, true),
			},
			want: false,
		},
		{
			name: "a failure is still a failure",
			results: []checks.EngineResult{
				res("os_version", "high", checks.StatusPass, false),
				res("disk_encryption", "critical", checks.StatusFail, false),
			},
			want: false,
		},
		{
			name: "an errored check still denies compliance",
			results: []checks.EngineResult{
				res("os_version", "high", checks.StatusPass, false),
				res("integrity", "high", checks.StatusError, false),
			},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := summarise(t, tc.results)
			if got.Compliant != tc.want {
				t.Fatalf("compliant = %v, want %v (passed=%d failed=%d warned=%d errored=%d unsupported=%d)",
					got.Compliant, tc.want, got.Passed, got.Failed, got.Warned, got.Errored, got.Unsupported)
			}
		})
	}
}

// TestUnsupportedIsCountedSeparatelyFromWarnings. The counts reach the user's
// screen, so a check that could not run must not be presented as a warning
// about the device: those are two different sentences and only one of them is
// about the phone in their hand.
func TestUnsupportedIsCountedSeparatelyFromWarnings(t *testing.T) {
	got := summarise(t, []checks.EngineResult{
		res("firewall", "medium", checks.StatusWarn, false),
		res("disk_encryption", "critical", checks.StatusWarn, true),
		res("screen_lock", "high", checks.StatusWarn, true),
	})

	if got.Warned != 1 {
		t.Errorf("warned = %d, want 1 — only the firewall check actually warned", got.Warned)
	}
	if got.Unsupported != 2 {
		t.Errorf("unsupported = %d, want 2", got.Unsupported)
	}
}

// TestTheSummaryTellsTheClientWhichChecksCouldNotRun: the per-check flag has
// to survive into the JSON, or the app can show a count and not say which
// ones, which is the least useful possible version of this.
func TestTheSummaryTellsTheClientWhichChecksCouldNotRun(t *testing.T) {
	got := summarise(t, []checks.EngineResult{
		res("agent_version", "low", checks.StatusPass, false),
		res("disk_encryption", "critical", checks.StatusWarn, true),
	})

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back struct {
		Compliant   bool `json:"compliant"`
		Unsupported int  `json:"unsupported"`
		Checks      []struct {
			Type        string `json:"type"`
			Unsupported bool   `json:"unsupported"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Compliant {
		t.Error("the payload claims compliance with an unsupported check present")
	}
	if back.Unsupported != 1 {
		t.Errorf("payload unsupported = %d, want 1", back.Unsupported)
	}
	var named bool
	for _, c := range back.Checks {
		if c.Type == "disk_encryption" && c.Unsupported {
			named = true
		}
		if c.Type == "agent_version" && c.Unsupported {
			t.Error("a check that ran is marked unsupported in the payload")
		}
	}
	if !named {
		t.Error("the payload does not say WHICH check could not run")
	}
}

// TestPostureRunsAndSummarises is the one case that exercises the real
// Engine.Posture() — it must produce a parseable payload on whatever platform
// the test runs on, so the summariser above cannot drift from the code path
// the GUI actually calls.
func TestPostureRunsAndSummarises(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	out, err := e.Posture()
	if err != nil {
		t.Fatalf("Posture: %v", err)
	}
	var got posturePayload
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("Posture returned unparseable JSON (%q): %v", out, err)
	}
	if len(got.Checks) == 0 {
		t.Fatal("Posture ran no checks at all")
	}
	// The arithmetic the GUI depends on, re-derived here: whatever this
	// platform supports, compliance and the unsupported count must agree.
	if got.Compliant && got.Unsupported > 0 {
		t.Errorf("compliant with %d unsupported check(s) — the fix is not in the live path",
			got.Unsupported)
	}
}
