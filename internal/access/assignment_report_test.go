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

// TestReportSummaryExcludesIncompleteUsers: a user whose evaluation failed
// (pillar lookup or assignment lookup) must be excluded from the diff
// entirely — no would-deny entries attributed to them in either direction —
// and the summary must say how many users were skipped, so a clean report
// can't be confused with a silently incomplete one.
//
// handleAssignmentReport itself needs a live DB (ziti_identities/applications
// queries plus collectZitiPillar), so simulating a mid-loop failure there
// would need a fair amount of fixture/mock scaffolding. buildReport is the
// pure seam that turns (reachable, assigned, incompleteUsers) into the actual
// API summary, so a failed user is represented here the same way the handler
// produces it: simply absent from both reachable and assigned, with the
// failure counted separately in incompleteUsers.
func TestReportSummaryExcludesIncompleteUsers(t *testing.T) {
	reachable := map[string][]string{
		"alice": {"app-es"},
		// "carol" is intentionally absent: her collectZitiPillar (or
		// AppsForUser) call failed, so the handler never adds her to either
		// map — she must not read as "loses nothing" nor "loses everything".
	}
	assigned := map[string][]string{
		"alice": {"app-es"},
	}
	names := map[string]string{"alice": "Alice", "carol": "Carol"}
	appNames := map[string]string{"app-es": "ES"}

	// One of two users evaluated, one counted incomplete.
	entries, summary := buildReport(reachable, assigned, names, appNames, 1, 1, 2)

	if len(entries) != 0 {
		t.Fatalf("expected no would-deny entries (alice is fully covered, carol is excluded), got %+v", entries)
	}
	for _, e := range entries {
		if e.UserID == "carol" {
			t.Errorf("carol's failed lookup must not produce a would-deny entry: %+v", e)
		}
	}
	if got := summary["incomplete_users"]; got != 1 {
		t.Errorf("summary incomplete_users = %v, want 1", got)
	}
	if got := summary["would_deny"]; got != 0 {
		t.Errorf("summary would_deny = %v, want 0", got)
	}
	if got := summary["users"]; got != 0 {
		t.Errorf("summary users = %v, want 0 (no affected users)", got)
	}
	// The denominator travels with the summary: "nothing to take away" is only
	// meaningful next to how much of the org was actually looked at.
	if got := summary["users_evaluated"]; got != 1 {
		t.Errorf("summary users_evaluated = %v, want 1", got)
	}
	if got := summary["users_total"]; got != 2 {
		t.Errorf("summary users_total = %v, want 2", got)
	}
}
