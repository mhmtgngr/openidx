package access

import "testing"

// TestReportDiffsReachAgainstAssignment: the report answers "who loses what when
// the flag flips". Ziti reach is structural, not per-request, so it is computed
// as a diff rather than logged on a denial.
func TestReportDiffsReachAgainstAssignment(t *testing.T) {
	reachable := map[string][]string{
		"alice": {"app-es", "app-ng"},
		"bob":   {"app-es"},
	}
	assigned := map[string][]string{
		"alice": {"app-es"},
		"bob":   {},
	}

	got := diffReachability(reachable, assigned)

	if len(got) != 2 {
		t.Fatalf("got %d would-deny entries, want 2 (alice loses app-ng, bob loses app-es): %+v", len(got), got)
	}
	for _, e := range got {
		if e.EnforcementPoint != "ziti" {
			t.Errorf("entry %+v: enforcement point should be ziti", e)
		}
		if e.Reason == "" {
			t.Errorf("entry %+v: reason must say why", e)
		}
		if e.UserID == "alice" && e.ApplicationID != "app-ng" {
			t.Errorf("alice should only lose app-ng, got %q", e.ApplicationID)
		}
		if e.UserID == "bob" && e.ApplicationID != "app-es" {
			t.Errorf("bob should lose app-es, got %q", e.ApplicationID)
		}
	}
}

// TestReportEmptyWhenAssignmentsCoverReach: nothing to report once assignment
// already grants everything currently reachable — the signal that it is safe to
// flip ACCESS_ASSIGNMENT_ENFORCE.
func TestReportEmptyWhenAssignmentsCoverReach(t *testing.T) {
	same := map[string][]string{"alice": {"app-es"}}
	if got := diffReachability(same, same); len(got) != 0 {
		t.Errorf("expected no entries, got %+v", got)
	}
}
