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
	entries, summary := buildReport(reachable, assigned, names, appNames, reportCounts{
		IncompleteUsers:    1,
		UsersEvaluated:     1,
		UsersTotal:         2,
		EvaluationComplete: evaluationComplete(ReachabilityFromController, 1, 1),
	})

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
	// A user the report could not finish is exactly the case the go/no-go must
	// refuse, whatever the diff looks like.
	if got := summary["evaluation_complete"]; got != false {
		t.Errorf("summary evaluation_complete = %v, want false while a user is incomplete", got)
	}
}

// TestDiffReachabilityDeduplicatesAUsersIdentities: a user's reach is the union
// over all their enrolled devices, so the same application arrives once per
// identity. Emitting one entry per arrival inflates would_deny N× while `users`
// stays at one, leaving the two halves of the same summary contradicting each
// other.
func TestDiffReachabilityDeduplicatesAUsersIdentities(t *testing.T) {
	// ann has a laptop and a phone; both identities reach app-es.
	reachable := map[string][]string{"ann": {"app-es", "app-es"}}
	assigned := map[string][]string{}

	entries, summary := buildReport(reachable, assigned,
		map[string]string{"ann": "Ann"}, map[string]string{"app-es": "ES"},
		reportCounts{UsersEvaluated: 1, UsersTotal: 1,
			EvaluationComplete: evaluationComplete(ReachabilityFromController, 0, 1)})

	if len(entries) != 1 {
		t.Fatalf("got %d would-deny entries for one user losing one application, want 1: %+v",
			len(entries), entries)
	}
	if got := summary["would_deny"]; got != 1 {
		t.Errorf("summary would_deny = %v, want 1", got)
	}
	if got := summary["users"]; got != 1 {
		t.Errorf("summary users = %v, want 1", got)
	}
	// The invariant the duplication broke: one affected user cannot account for
	// more would-deny entries than they have distinct applications.
	if summary["would_deny"].(int) < summary["users"].(int) {
		t.Errorf("would_deny %v is inconsistent with users %v", summary["would_deny"], summary["users"])
	}
}

// TestEvaluationCompleteIsComputedOnce pins the ruling on what "complete"
// means, so that every consumer reads one rule instead of re-deriving it.
func TestEvaluationCompleteIsComputedOnce(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		incomplete int
		evaluated  int
		want       bool
	}{
		{"clean, everyone evaluated", ReachabilityFromController, 0, 4, true},
		// The ruling: identity-less users do not block completeness. Two of the
		// org's six users have no Ziti identity and so have no Ziti reach to
		// lose; the four that do were all evaluated cleanly.
		{"some users have no identity", ReachabilityFromController, 0, 4, true},
		// The case the strict rule was written for survives: an org whose sync
		// has never run evaluates nobody.
		{"nobody evaluated", ReachabilityFromController, 0, 0, false},
		{"a user could not be finished", ReachabilityFromController, 1, 4, false},
		{"reach unknown", ReachabilityUnavailable, 0, 4, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluationComplete(tc.source, tc.incomplete, tc.evaluated); got != tc.want {
				t.Fatalf("evaluationComplete(%q, %d, %d) = %v, want %v",
					tc.source, tc.incomplete, tc.evaluated, got, tc.want)
			}
		})
	}
}
