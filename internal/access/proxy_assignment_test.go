package access

import "testing"

// TestProxyAssignmentDecision pins the three-way behaviour: routes with no
// application are untouched, report mode never denies, and enforcement denies an
// unassigned caller. Under enforcement the predicate REPLACES the role/group
// check for app-backed routes — checking both would be the intersect model the
// design rejected.
func TestProxyAssignmentDecision(t *testing.T) {
	cases := []struct {
		name       string
		appID      string
		assigned   bool
		enforce    bool
		legacyOK   bool
		wantAllow  bool
		wantReport bool
	}{
		{"no application, legacy allows", "", false, true, true, true, false},
		{"no application, legacy denies", "", false, true, false, false, false},
		{"app-backed, report mode, unassigned", "app-1", false, false, true, true, true},
		{"app-backed, report mode, assigned", "app-1", true, false, true, true, false},
		{"app-backed, enforced, unassigned", "app-1", false, true, true, false, true},
		{"app-backed, enforced, assigned", "app-1", true, true, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, report := proxyAssignmentDecision(tc.appID, tc.assigned, tc.enforce, tc.legacyOK)
			if allow != tc.wantAllow {
				t.Errorf("allow = %v, want %v", allow, tc.wantAllow)
			}
			if report != tc.wantReport {
				t.Errorf("report = %v, want %v", report, tc.wantReport)
			}
		})
	}
}
