package identity

import (
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
)

func TestAssessPushLiveness(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour
	at := func(daysAgo int) *time.Time {
		v := now.Add(-time.Duration(daysAgo) * 24 * time.Hour)
		return &v
	}
	fresh := PushMFADevice{Enabled: true, CreatedAt: *at(200), LastSeenAt: at(3)}
	stale := PushMFADevice{Enabled: true, CreatedAt: *at(200), LastSeenAt: at(45)}
	// A row the migration could not backfill: its last approval stands in.
	staleByLastUse := PushMFADevice{Enabled: true, CreatedAt: *at(200), LastUsedAt: at(31)}
	// No approval either: the registration stands in.
	freshByCreation := PushMFADevice{Enabled: true, CreatedAt: *at(1)}
	swept := PushMFADevice{Enabled: false, CreatedAt: *at(200), LastSeenAt: at(100), DisabledAt: at(10), DisabledReason: PushDisabledStale}
	switchedOff := PushMFADevice{Enabled: false, CreatedAt: *at(2), LastSeenAt: at(2)}

	cases := []struct {
		name                    string
		devices                 []PushMFADevice
		fresh, stale, suspended int
		offerable, unseen       bool
		lastSeen                *time.Time
	}{
		{"none", nil, 0, 0, 0, false, false, nil},
		{"one fresh", []PushMFADevice{fresh}, 1, 0, 0, true, false, fresh.LastSeenAt},
		{"one stale", []PushMFADevice{stale}, 0, 1, 0, true, true, stale.LastSeenAt},
		{"stale by last use", []PushMFADevice{staleByLastUse}, 0, 1, 0, true, true, staleByLastUse.LastUsedAt},
		{"fresh by creation", []PushMFADevice{freshByCreation}, 1, 0, 0, true, false, &freshByCreation.CreatedAt},
		{"fresh beside stale", []PushMFADevice{stale, fresh}, 1, 1, 0, true, false, fresh.LastSeenAt},
		{"swept only", []PushMFADevice{swept}, 0, 0, 1, false, true, swept.LastSeenAt},
		// A device the user switched off was never a factor and still is not:
		// it neither counts nor stands as a sighting.
		{"switched off only", []PushMFADevice{switchedOff}, 0, 0, 0, false, false, nil},
		{"swept and stale", []PushMFADevice{swept, stale}, 0, 1, 1, true, true, stale.LastSeenAt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := AssessPushLiveness(tc.devices, now, window)
			if l.Fresh != tc.fresh || l.Stale != tc.stale || l.Suspended != tc.suspended {
				t.Fatalf("got fresh=%d stale=%d suspended=%d, want %d/%d/%d",
					l.Fresh, l.Stale, l.Suspended, tc.fresh, tc.stale, tc.suspended)
			}
			if l.Offerable() != tc.offerable || l.Unseen() != tc.unseen {
				t.Fatalf("offerable=%v unseen=%v, want %v/%v", l.Offerable(), l.Unseen(), tc.offerable, tc.unseen)
			}
			switch {
			case tc.lastSeen == nil && l.LastSeen != nil:
				t.Fatalf("LastSeen = %v, want nil", l.LastSeen)
			case tc.lastSeen != nil && (l.LastSeen == nil || !l.LastSeen.Equal(*tc.lastSeen)):
				t.Fatalf("LastSeen = %v, want %v", l.LastSeen, tc.lastSeen)
			}
		})
	}
}

// The challenge goes to the phone that answered most recently, not to the
// install that registered last.
func TestMostRecentlySeenEnabled(t *testing.T) {
	now := time.Now()
	old, recent := now.Add(-40*24*time.Hour), now.Add(-time.Hour)
	devices := []PushMFADevice{
		{ID: "newest-install-never-seen", Enabled: true, CreatedAt: now.Add(-50 * 24 * time.Hour), LastSeenAt: &old},
		{ID: "off", Enabled: false, CreatedAt: now, LastSeenAt: &now},
		{ID: "the-real-phone", Enabled: true, CreatedAt: now.Add(-300 * 24 * time.Hour), LastSeenAt: &recent},
	}
	if got := mostRecentlySeenEnabled(devices); got == nil || got.ID != "the-real-phone" {
		t.Fatalf("target = %+v, want the-real-phone", got)
	}
	if got := mostRecentlySeenEnabled([]PushMFADevice{{Enabled: false}}); got != nil {
		t.Fatalf("no enabled device must yield nil, got %+v", got)
	}
}

func TestPushDeviceStaleAfterDefaults(t *testing.T) {
	if got := (&Service{}).PushDeviceStaleAfter(); got != 30*24*time.Hour {
		t.Fatalf("no config: %v, want 30 days", got)
	}
	cfg := &config.Config{}
	cfg.PushMFA.StaleDeviceDays = 7
	if got := (&Service{cfg: cfg}).PushDeviceStaleAfter(); got != 7*24*time.Hour {
		t.Fatalf("configured: %v, want 7 days", got)
	}
}

func TestSummarizeSignInMethods(t *testing.T) {
	m := &SignInMethods{PushDevices: []SignInPushDevice{{Status: PushStatusStale}, {Status: PushStatusDisabled}}}
	summarizeSignInMethods(m)
	if !m.Summary.OnlyStalePush || m.Summary.UsableFactors != 0 {
		t.Fatalf("push-only with no phone seen: %+v", m.Summary)
	}
	m.PushDevices = append(m.PushDevices, SignInPushDevice{Status: PushStatusActive})
	summarizeSignInMethods(m)
	if m.Summary.OnlyStalePush || m.Summary.UsableFactors != 1 {
		t.Fatalf("one phone seen: %+v", m.Summary)
	}
	m = &SignInMethods{TOTP: &SignInTOTP{Enabled: true}, PushDevices: []SignInPushDevice{{Status: PushStatusStale}}}
	summarizeSignInMethods(m)
	if m.Summary.OnlyStalePush || m.Summary.UsableFactors != 1 {
		t.Fatalf("TOTP beside a stale phone: %+v", m.Summary)
	}
	m = &SignInMethods{PushDevices: []SignInPushDevice{{Status: PushStatusSwitchedOff}}}
	summarizeSignInMethods(m)
	if m.Summary.OnlyStalePush {
		t.Fatalf("a switched-off phone is not a factor: %+v", m.Summary)
	}
}
