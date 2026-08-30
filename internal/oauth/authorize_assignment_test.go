package oauth

import "testing"

// TestAuthorizeAssignmentDecision: the gate is opt-in per client so deploy one
// cannot lock an operator out of a first-party client that has no assignments.
func TestAuthorizeAssignmentDecision(t *testing.T) {
	cases := []struct {
		name       string
		requires   bool
		assigned   bool
		enforce    bool
		wantIssue  bool
		wantReport bool
	}{
		{"client does not require assignment", false, false, true, true, false},
		{"requires, assigned", true, true, true, true, false},
		{"requires, unassigned, report mode", true, false, false, true, true},
		{"requires, unassigned, enforced", true, false, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issue, report := authorizeAssignmentDecision(tc.requires, tc.assigned, tc.enforce)
			if issue != tc.wantIssue {
				t.Errorf("issue = %v, want %v", issue, tc.wantIssue)
			}
			if report != tc.wantReport {
				t.Errorf("report = %v, want %v", report, tc.wantReport)
			}
		})
	}
}
