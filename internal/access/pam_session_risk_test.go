package access

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestScorePAMSession(t *testing.T) {
	cases := []struct {
		name    string
		sig     pamRiskSignals
		wantMin int
		wantMax int
	}{
		{"idle low-risk business-hours short", pamRiskSignals{OffHours: false, DurationMinutes: 10, UserRiskScore: 0}, 0, 5},
		{"high user risk dominates", pamRiskSignals{OffHours: false, DurationMinutes: 10, UserRiskScore: 90}, 50, 60},
		{"off-hours adds", pamRiskSignals{OffHours: true, DurationMinutes: 10, UserRiskScore: 0}, 25, 25},
		{"long session adds", pamRiskSignals{OffHours: false, DurationMinutes: 300, UserRiskScore: 0}, 20, 20},
		{"everything caps at 100", pamRiskSignals{OffHours: true, DurationMinutes: 600, UserRiskScore: 100}, 100, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scorePAMSession(c.sig)
			if got < c.wantMin || got > c.wantMax {
				t.Fatalf("scorePAMSession(%+v) = %d; want [%d,%d]", c.sig, got, c.wantMin, c.wantMax)
			}
			if got < 0 || got > 100 {
				t.Fatalf("score %d out of range 0-100", got)
			}
		})
	}
}

func TestIsOffHours(t *testing.T) {
	mk := func(h int) time.Time { return time.Date(2026, 7, 29, h, 0, 0, 0, time.Local) }
	for h := 0; h < 24; h++ {
		want := h < 7 || h >= 20
		if got := isOffHours(mk(h)); got != want {
			t.Fatalf("isOffHours(%02d:00) = %v; want %v", h, got, want)
		}
	}
}

// The gate must default to a safe no-op so enabling the scorer is deliberate.
func TestRiskScorerGateDefaultsSafe(t *testing.T) {
	p := NewPAMSessionRiskScorer(nil, 0, "", 0, zap.NewNop())
	if p.gate != "off" {
		t.Fatalf("empty gate must default to off, got %q", p.gate)
	}
	if p.threshold != 80 {
		t.Fatalf("zero threshold must default to 80, got %d", p.threshold)
	}
	if p.interval <= 0 {
		t.Fatalf("interval must be positive, got %s", p.interval)
	}
}

// The scorer used to compare the raw setting, so any spelling other than
// exactly "off" or "observe" fell through to enforcement and terminated
// sessions. It now reads the gate the way every other gate does.
func TestPAMSessionRiskGateIsNormalised(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "off"},
		{"off", "off"},
		{"Off", "off"},
		{" OFF ", "off"},
		{"observe", "observe"},
		{" OBSERVE ", "observe"},
		{"Observe", "observe"},
		{"enforce", "enforce"},
		{"Enforce", "enforce"},
		// Unknown values never reach here in a running service, because config
		// refuses them at startup; if one does, it must not enforce.
		{"enfroce", "off"},
	} {
		p := NewPAMSessionRiskScorer(nil, 0, tc.in, 0, zap.NewNop())
		if p.gate != tc.want {
			t.Errorf("gate %q read as %q, want %q", tc.in, p.gate, tc.want)
		}
	}
}
