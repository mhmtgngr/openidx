package access

import (
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

// TestTheReachMatrixIsTheWholeDecision.
//
// Every row here is a privileged session someone can launch today. The two that
// matter most are the two the product produces BY DEFAULT: an entry created
// without a deliberate reach choice gets 'direct' (migration v82 made it the
// column default), and a website entry brokers nothing at all. Both open a path
// to the target that never touches the overlay, and before this gate existed
// neither was refused or even recorded.
func TestTheReachMatrixIsTheWholeDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reachMode  string
		protocol   string
		overlayOK  bool
		wantCode   string
		wantInText string
	}{
		{"an rdp entry over the overlay", "ziti", "rdp", true, "", ""},
		{"an ssh entry over the overlay", "ziti", "ssh", true, "", ""},
		{"reach mode spelled oddly but still ziti", " ZITI ", "rdp", true, "", ""},

		{"the default an entry is created with", "direct", "rdp", false,
			"ztna_required_direct_reach", "reach_mode=direct"},
		{"a reach mode that arrived empty", "", "ssh", false,
			"ztna_required_direct_reach", "direct (unset)"},
		{"a website entry, which brokers nothing", "ziti", "", false,
			"ztna_required_website_entry", "returns a URL for the browser"},
		{"a website entry with direct reach", "direct", "", false,
			"ztna_required_website_entry", "brokers no session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, code, reason := pamReachIsOverlayOnly(tc.reachMode, tc.protocol)
			if ok != tc.overlayOK {
				t.Fatalf("overlay-only = %v, want %v (reach=%q protocol=%q)",
					ok, tc.overlayOK, tc.reachMode, tc.protocol)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if tc.wantInText != "" && !strings.Contains(reason, tc.wantInText) {
				t.Errorf("the refusal does not tell the operator what is wrong:\n  got:  %s\n  want a mention of %q",
					reason, tc.wantInText)
			}
			if ok && reason != "" {
				t.Errorf("an allowed launch carries a refusal reason: %q", reason)
			}
		})
	}
}

// TestTheModeDecidesRefuseVersusRecord. off changes nothing, observe records
// without refusing, enforce refuses. The middle one is not decoration: an
// operator turning this on needs the list of entries that will stop working,
// and the only place that list comes from is attempts being recorded first.
func TestTheModeDecidesRefuseVersusRecord(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		want     ztnaMode
		refuses  bool
		observes bool
	}{
		{"", ztnaOff, false, false},
		{"off", ztnaOff, false, false},
		{"observe", ztnaObserve, false, true},
		{"enforce", ztnaEnforce, true, false},
		{"ENFORCE", ztnaEnforce, true, false},
		{"  enforce  ", ztnaEnforce, true, false},
		// A typo must not enforce and must not silently look like it does.
		// This gate refuses privileged sessions; "enfroce" turning into "off"
		// is the safe direction, and ReportModeGates prints the value so the
		// operator sees "off" where they expected otherwise.
		{"enfroce", ztnaOff, false, false},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			s := &Service{config: &config.Config{PAMRequireZTNA: tc.mode}}
			if got := s.pamZTNAMode(); got != tc.want {
				t.Fatalf("pamZTNAMode() = %v, want %v", got, tc.want)
			}
			if (s.pamZTNAMode() == ztnaEnforce) != tc.refuses {
				t.Errorf("enforce = %v, want %v", !tc.refuses, tc.refuses)
			}
			if (s.pamZTNAMode() == ztnaObserve) != tc.observes {
				t.Errorf("observe = %v, want %v", !tc.observes, tc.observes)
			}
		})
	}
}

// TestNoConfigIsOff: a Service built without config (bare construction in
// tests, and any future caller that forgets) must not start refusing every
// privileged session. Off is the safe reading of "nothing was configured".
func TestNoConfigIsOff(t *testing.T) {
	if got := (&Service{}).pamZTNAMode(); got != ztnaOff {
		t.Fatalf("a Service with no config reports mode %v, want off", got)
	}
}
