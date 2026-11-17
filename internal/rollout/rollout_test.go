package rollout

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// fleet builds n in-ring live devices, on lists how many are on the target and
// failed how many report a failed update (the rest are behind and idle).
func fleet(n, on, failed int) []Device {
	var ds []Device
	for i := 0; i < n; i++ {
		d := Device{ID: fmt.Sprintf("d%d", i), Version: "0.5.0", Live: true, InRing: true}
		switch {
		case i < on:
			d.Version, d.Update = "0.6.0", UpdateOK
		case i < on+failed:
			d.Update, d.UpdateAt = UpdateFailed, now.Add(-time.Hour)
		}
		ds = append(ds, d)
	}
	return ds
}

// outOfRing marks every device as not reached by the ring.
func outOfRing(ds []Device) []Device {
	for i := range ds {
		ds[i].InRing = false
	}
	return ds
}

func in(percent int, paused bool, since time.Duration, ds []Device) Input {
	return Input{Now: now, Target: "0.6.0", Settings: Settings{Percent: percent, Paused: paused, ChangedAt: now.Add(-since)}, Devices: ds}
}

func TestJudgeRollout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     Input
		status Status
		first  string // first reason
		prop   *Proposal
	}{
		{"no target", Input{Now: now, Devices: fleet(3, 0, 0)}, StatusNoTarget, ReasonNoTarget, nil},
		{"a healthy ring that has soaked widens", in(5, false, 2*time.Hour, fleet(10, 10, 0)), StatusReady, ReasonReady, &Proposal{ActionAdvance, 25}},
		{"widening starts from nobody", in(0, false, 2*time.Hour, outOfRing(fleet(10, 0, 0))), StatusReady, ReasonEmptyRing, &Proposal{ActionAdvance, 5}},
		{"a ring that has not soaked waits", in(5, false, 10*time.Minute, fleet(10, 10, 0)), StatusSoaking, ReasonSoaking, nil},
		{"devices that have not updated yet are waited for", in(25, false, 2*time.Hour, fleet(10, 5, 0)), StatusSoaking, ReasonWaiting, nil},
		{"90 percent is enough", in(25, false, 2*time.Hour, fleet(10, 9, 0)), StatusReady, ReasonReady, &Proposal{ActionAdvance, 50}},
		{"two failures in ten attempts is unhealthy: pause", in(25, false, 2*time.Hour, fleet(10, 8, 2)), StatusUnhealthy, ReasonFailures, &Proposal{Action: ActionPause}},
		{"one failure among many is noise", in(25, false, 2*time.Hour, fleet(20, 19, 1)), StatusReady, ReasonReady, &Proposal{ActionAdvance, 50}},
		{"one failure in a tiny sample is not noise", in(5, false, 2*time.Hour, fleet(3, 2, 1)), StatusUnhealthy, ReasonFailures, &Proposal{Action: ActionPause}},
		{"paused stays paused and proposes nothing", in(25, true, 2*time.Hour, fleet(10, 8, 2)), StatusPaused, ReasonPaused, nil},
		{"done at 100", in(100, false, 2*time.Hour, fleet(10, 10, 0)), StatusComplete, ReasonAllOnTgt, nil},
		{"at 100 with stragglers it is not done and not widened", in(100, false, 2*time.Hour, fleet(10, 5, 0)), StatusSoaking, ReasonWaiting, nil},
		{"an empty ring has nothing to wait for", in(5, false, 2*time.Hour, nil), StatusReady, ReasonEmptyRing, &Proposal{ActionAdvance, 25}},
	} {
		v := JudgeRollout(tc.in)
		if v.Status != tc.status || len(v.Reasons) == 0 || v.Reasons[0] != tc.first || !reflect.DeepEqual(v.Proposal, tc.prop) {
			t.Errorf("%s: got %s %v %+v, want %s %s %+v", tc.name, v.Status, v.Reasons, v.Proposal, tc.status, tc.first, tc.prop)
		}
	}
}

func TestOfflineDevicesAreNotWaitedFor(t *testing.T) {
	ds := fleet(10, 9, 0)
	ds[9].Live = false // the tenth is switched off
	v := JudgeRollout(in(25, false, 2*time.Hour, ds))
	if v.Status != StatusReady || v.Counts.Offline != 1 {
		t.Errorf("an offline device blocked the rollout: %+v", v)
	}
	found := false
	for _, r := range v.Reasons {
		found = found || r == ReasonOfflineIgn
	}
	if !found {
		t.Errorf("the offline device was ignored without saying so: %v", v.Reasons)
	}
}

func TestOldFailuresAndOtherRingsDoNotCount(t *testing.T) {
	ds := fleet(10, 8, 2)
	for i := range ds {
		if ds[i].Update == UpdateFailed {
			ds[i].UpdateAt = now.Add(-48 * time.Hour) // a day and more ago
		}
	}
	if v := JudgeRollout(in(25, false, 2*time.Hour, ds)); v.Status == StatusUnhealthy {
		t.Errorf("a failure from two days ago paused the rollout: %+v", v)
	}
	ds = fleet(10, 8, 2)
	for i := range ds {
		if ds[i].Update == UpdateFailed {
			ds[i].InRing = false // the ring does not reach it
		}
	}
	if v := JudgeRollout(in(25, false, 2*time.Hour, ds)); v.Counts.Failed != 0 {
		t.Errorf("a device outside the ring was counted: %+v", v.Counts)
	}
}

func TestVersionsCompareWithoutTheLeadingV(t *testing.T) {
	if !SameRelease("v0.6.0", "0.6.0") || SameRelease("", "") || SameRelease("0.6.0", "0.6.1") {
		t.Error("SameRelease")
	}
	v := JudgeRollout(Input{Now: now, Target: "v0.6.0", Settings: Settings{Percent: 100, ChangedAt: now.Add(-3 * time.Hour)}, Devices: fleet(4, 4, 0)})
	if v.Status != StatusComplete {
		t.Errorf("v-prefixed target: %+v", v)
	}
}

func TestRings(t *testing.T) {
	for p, want := range map[int]int{0: 5, 5: 25, 24: 25, 25: 50, 50: 100, 99: 100, 100: 0} {
		if got := NextRingAbove(p); got != want {
			t.Errorf("NextRingAbove(%d) = %d, want %d", p, got, want)
		}
	}
}

// Every reason has words in every console locale. The console shows the raw
// code for one it does not know, which an administrator cannot act on.
func TestEveryReasonHasWordsInTheConsole(t *testing.T) {
	for _, locale := range []string{"en", "tr"} {
		src, err := os.ReadFile("../../web/admin-console/src/i18n/locales/" + locale + ".ts")
		if err != nil {
			t.Fatal(err)
		}
		_, after, found := strings.Cut(string(src), "      rollout: {")
		if !found {
			t.Fatalf("%s has no rollout block", locale)
		}
		_, reasons, found := strings.Cut(after, "        reason: {")
		if !found {
			t.Fatalf("%s has no rollout reasons", locale)
		}
		block, _, _ := strings.Cut(reasons, "\n        },")
		for _, code := range AllReasons {
			if !regexp.MustCompile(`\n          ` + code + `: '.+',`).MatchString(block) {
				t.Errorf("%s.ts has no words for the rollout reason %s", locale, code)
			}
		}
	}
}
