package accessplan

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func facts() Facts {
	return Facts{ResourceFound: true, ResourceID: "r1", ResourceName: "Wiki", ResourceKind: "web", ResourceEnabled: true,
		GroupFound: true, GroupID: "g1", GroupName: "Engineering", GroupMembers: 8, OrgUsers: 100}
}

func TestPlanOpenAccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mut     func(*Facts)
		status  Status
		codes   []string // blockers, notes, then risks, in order
		hasStep bool
	}{
		{"a clean request is ready", func(f *Facts) {}, StatusReady, nil, true},
		{"no such resource", func(f *Facts) { f.ResourceFound = false }, StatusBlocked, []string{BlockerNoResource}, false},
		{"no such group", func(f *Facts) { f.GroupFound = false }, StatusBlocked, []string{BlockerNoGroup}, false},
		{"both missing says both", func(f *Facts) { f.ResourceFound, f.GroupFound = false, false }, StatusBlocked, []string{BlockerNoResource, BlockerNoGroup}, false},
		{"a disabled resource cannot be opened", func(f *Facts) { f.ResourceEnabled = false }, StatusBlocked, []string{BlockerDisabled}, false},
		{"already granted is nothing to do", func(f *Facts) { f.AlreadyGranted = true }, StatusNoop, []string{NoteAlready}, false},
		{"an empty group gains no one, which is worth saying", func(f *Facts) { f.GroupMembers = 0 }, StatusReady, []string{RiskEmptyGroup}, true},
		{"half the organization is wide", func(f *Facts) { f.GroupMembers = 50 }, StatusReady, []string{RiskWideGroup}, true},
		{"just under half is not", func(f *Facts) { f.GroupMembers = 49 }, StatusReady, nil, true},
		{"in a tiny organization half the people is not wide", func(f *Facts) { f.OrgUsers, f.GroupMembers = 6, 4 }, StatusReady, nil, true},
		{"a privileged resource says so", func(f *Facts) { f.ResourceKind = KindPrivileged }, StatusReady, []string{RiskPrivileged}, true},
		{"privileged and wide say both", func(f *Facts) { f.ResourceKind, f.GroupMembers = KindPrivileged, 60 }, StatusReady, []string{RiskWideGroup, RiskPrivileged}, true},
	} {
		f := facts()
		tc.mut(&f)
		p := PlanOpenAccess(f)
		got := append(append(append([]string{}, p.Blockers...), p.Notes...), p.Risks...)
		if len(got) == 0 {
			got = nil
		}
		if p.Status != tc.status || !reflect.DeepEqual(got, tc.codes) || (len(p.Steps) == 1) != tc.hasStep {
			t.Errorf("%s: got %s %v steps=%d, want %s %v step=%v", tc.name, p.Status, got, len(p.Steps), tc.status, tc.codes, tc.hasStep)
		}
	}
}

func TestTheStepNamesWhatItChanges(t *testing.T) {
	p := PlanOpenAccess(facts())
	want := []Step{{Action: ActionGrantGroup, ResourceID: "r1", GroupID: "g1"}}
	if !reflect.DeepEqual(p.Steps, want) {
		t.Errorf("steps = %+v, want %+v", p.Steps, want)
	}
}

// Every code has words in every console locale; the console shows the raw
// code otherwise, which an administrator cannot act on.
func TestEveryCodeHasWordsInTheConsole(t *testing.T) {
	for _, locale := range []string{"en", "tr"} {
		src, err := os.ReadFile("../../web/admin-console/src/i18n/locales/" + locale + ".ts")
		if err != nil {
			t.Fatal(err)
		}
		_, after, found := strings.Cut(string(src), "  accessPlans: {")
		if !found {
			t.Fatalf("%s has no accessPlans block", locale)
		}
		_, codes, found := strings.Cut(after, "    code: {")
		if !found {
			t.Fatalf("%s has no accessPlans codes", locale)
		}
		block, _, _ := strings.Cut(codes, "\n    },")
		for _, code := range AllCodes {
			if !regexp.MustCompile(`\n      ` + code + `: '.+',`).MatchString(block) {
				t.Errorf("%s.ts has no words for the access plan code %s", locale, code)
			}
		}
	}
}
