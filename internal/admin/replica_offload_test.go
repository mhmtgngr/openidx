package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE ADMIN PLANE'S READS, MOVED TO THE REPLICA ONE FEATURE AT A TIME.
//
// PostgresDB.Reader() serves read-mostly, lag-tolerant queries from the read
// replica and falls back to the primary when the replica is unreachable
// (internal/common/database/readerfallback.go). Moving the ADMIN plane's
// expensive reads onto it is the point of global-scale plan task 2.3: the
// console's aggregates are the queries that cost the most and tolerate a
// second of staleness best, and every one of them left on the primary is a
// backend the login path could have had.
//
// The plan is explicit that this must NOT be a bulk edit -- the lesson of task
// 2.1b, where 1,967 hand edits would each have been a chance to silently break
// a tenant scope. So it moves in feature-sized batches, and each batch is
// pinned here.
//
// TWO DIRECTIONS ARE GUARDED, because only one of them is obvious:
//
//   - a file listed below must use ONLY the replica, and must not write. A
//     write through Reader() is not a silent mistake -- a read-only
//     transaction answers SQLSTATE 25006 -- but it is an error in production
//     rather than in CI, which is the wrong place to find it.
//   - a file NOT listed must not use Reader() at all. That is what stops a
//     query being offloaded in passing, without anyone deciding whether it can
//     tolerate lag.

// offloadedToReplica names the files whose queries have moved, and why each is
// safe to serve from a lagging replica. The reason is mandatory: "this is a
// read" is not a reason, because a read-after-write is also a read.
var offloadedToReplica = map[string]string{
	"analytics_enhanced.go":   "aggregates over audit_events and login_history bucketed by day, hour and day-of-week; a console chart cannot show the difference a second of lag makes",
	"risk_analytics.go":       "risk scores and baselines computed from login_history; the profile is a report on past behaviour, not a decision gate -- the live decision is internal/risk on the primary",
	"predictive_analytics.go": "forecasts from daily and weekly buckets of audit_events and user_sessions; the input is days of history and the output is a trend",
	"dashboard.go":            "the overview tiles: counts of users, sessions and enrolled factors, plus the latest audit rows. Tiles, not gates -- nothing here authorises anything",
	"ai_intelligence.go":      "the intelligence panel: per-user risk averages from login_history, alert counts from security_alerts, and who has a factor enrolled. Every figure is a summary of the past shown on a screen; none of it decides anything",
	"pam_overview.go":         "the PAM overview counts: secrets by type, rotations due, active checkouts, pending access requests. A tile that says 12 instead of 13 for a second costs nothing -- the checkout itself is authorised elsewhere, on the primary",
}

// stayOnPrimary is the other half of the census, and the half that saves the
// next batch from re-deriving it. These files have reads and NO writes, so they
// look offloadable by the same test the batches above pass -- and they are not.
// The reason is recorded here so nobody has to work it out twice.
var stayOnPrimary = map[string]string{
	"dsar_processor.go": "a worker, not a page: it polls data_subject_requests for work it is about to act on. A lagging replica would hand it a request another replica already took, or hide one that is waiting -- the textbook read-after-write, and the reason Reader() exists to be opted into rather than assumed",
	"tilequery.go":      "a generic helper that runs whatever SQL its caller hands it. Offloading it would offload every caller at once, including ones nobody has read, which is exactly the decision this census exists to prevent being made by accident",

	// AND THE REST OF THE PACKAGE, for one measured reason.
	//
	// Every remaining file here writes as well as reads, and every one of them
	// is a CRUD surface. That matters because of what the console does after a
	// write: it is a TanStack Query application, and it invalidates the list it
	// has just changed. Counted: 384 invalidateQueries calls across 81 files,
	// out of 90 files that mutate at all. So "list" is not a lag-tolerant read
	// on these screens -- it is a read-after-write, issued milliseconds after
	// the POST returns. An administrator who creates a routing rule and does
	// not see it in the refreshed list does not wait; they create it again.
	//
	// That is the boundary of task 2.3 at FILE granularity, and batches 1 and 2
	// took everything on the other side of it. What remains is finer than a
	// file: the stats, score and trend handlers sitting inside these CRUD files
	// (ispm GetPostureScore and GetPostureTrends, mfa_management
	// MFAEnrollmentStats, ai_recommendations RecommendationStats, attestation
	// campaign progress) are lag-tolerant and cannot move while the guard works
	// per file. Moving them needs the census at function granularity, which is
	// the next piece of work rather than something to improvise here.
	"admin_audit.go":             "the admin audit log and settings history. Append-only, but the console opens it straight after the action that wrote the entry -- a reader who cannot see what they just did reports it as a lost audit record",
	"ai_agents.go":               "agent CRUD plus credential rotation: the rotate handler reads the agent it is about to re-key, and the console refetches the list after every create, suspend and activate",
	"ai_recommendations.go":      "recommendation CRUD: accept, dismiss and apply each write and then the list refetches, so a lagging read shows a recommendation the operator has already actioned",
	"attestation.go":             "attestation campaigns: launch reads the campaign it is about to send, and a decision written on an item must be visible on the next read or the reviewer decides it twice",
	"audit_archival.go":          "archival jobs read the policy and the archive rows they are about to act on; a stale read archives the wrong window or repeats one",
	"bulk_import_export.go":      "an import reads back what it just wrote to report per-row results; a lagging replica would report rows as failed that in fact landed",
	"bulk_operations.go":         "the most write-heavy file here: every read sits inside an operation that has just written, checking what to do next",
	"continuous_auth.go":         "continuous-auth policy and session risk: these reads gate a step-up, and a stale policy is a weaker policy than the one an administrator just saved",
	"deprovisioning.go":          "lifecycle policies and their executions: execute reads the policy it is about to run, and the execution list refetches the moment a run starts",
	"developer.go":               "developer settings CRUD, read back immediately after being written",
	"email_templates.go":         "template CRUD with a preview: preview renders the template the administrator has this second saved, so a stale read previews the previous version",
	"error_catalog.go":           "error-catalogue entries, read back immediately after being written",
	"federation.go":              "social providers and federation rules: a provider saved and not visible on the refetch reads as a failed save, and the operator saves it twice",
	"ibdr.go":                    "backup and restore records: a restore reads the record it is about to act on, which must be the one just written",
	"ispm.go":                    "posture findings and rules: dismiss and remediate write, then the list refetches. The score and trend reads in this file ARE lag-tolerant and are part of the finer opportunity noted above",
	"mfa_management.go":          "MFA policy CRUD. The policy decides whether a factor is required, so it belongs with the security-critical reads this package already keeps on the primary (see settings_repository.go); the enrollment-stats read here is lag-tolerant and part of the same follow-up",
	"notification_management.go": "routing rules and broadcasts: send reads the broadcast it is about to deliver and counts its recipients, and delete reads the status it gates on. Sending a superseded body, or sending twice, is not a stale tile",
	"privacy.go":                 "DSAR and consent records: a consent read that lags is a consent decision applied after it was withdrawn",
	"service.go":                 "the package's main surface, 49 reads across every admin resource, nearly all of them CRUD read-after-write. It moves query by query when its turn comes, not as a file",
	"sessions.go":                "session listing and termination: the list is refetched right after a terminate, and a session shown as live after it was revoked is the one answer this screen must never give",
	"settings_repository.go":     "already pinned by TestSettingsRepositoryGetUsesPrimary: system_settings carries password policy, RequireMFA and lockout, so a read must observe the latest write immediately -- a lagging replica would serve a weaker security policy",
	"tenant_branding.go":         "branding, tenant settings and custom domains, each read back by the console immediately after being saved",
}

// writeCalls are the pool methods that change data. None may appear in an
// offloaded file.
var writeCalls = regexp.MustCompile(`\.(Exec|Begin|CopyFrom|SendBatch)\(`)

func adminSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	// Vacuity guard: an empty package would make every assertion below pass.
	if len(out) < 20 {
		t.Fatalf("only %d source files in internal/admin; this guard is checking almost nothing", len(out))
	}
	return out
}

func readAdminFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// An offloaded file has finished the move: no query left on the primary, and
// no write at all.
func TestOffloadedFilesUseOnlyTheReplica(t *testing.T) {
	for _, name := range sortedOffloaded() {
		src := readAdminFile(t, name)

		if strings.Contains(src, "db.Pool") {
			t.Errorf("%s is declared offloaded but still queries db.Pool (the primary); finish the move or remove it from offloadedToReplica", name)
		}
		if m := writeCalls.FindString(src); m != "" {
			t.Errorf("%s is declared offloaded but calls %s: a write through Reader() is refused by the server with SQLSTATE 25006, in production rather than here", name, strings.Trim(m, ".("))
		}
		// Vacuity: a file that lost its queries would pass both checks above.
		if !strings.Contains(src, ".Reader().Query") {
			t.Errorf("%s is declared offloaded but holds no replica query; either it has no reads left or the move never happened", name)
		}
	}
}

// Every entry says why the query tolerates lag. A batch without a reason is a
// batch nobody decided.
func TestOffloadedFilesDeclareWhy(t *testing.T) {
	for _, name := range sortedOffloaded() {
		if reason := strings.TrimSpace(offloadedToReplica[name]); len(reason) < 30 {
			t.Errorf("%s: the offload reason is missing or too thin (%q). Say what makes this query lag-tolerant; \"it is a read\" is not a reason, because a read-after-write is also a read", name, reason)
		}
		if _, err := os.Stat(name); err != nil {
			t.Errorf("offloadedToReplica names %s, which is not in this package: %v", name, err)
		}
	}
}

// The direction that is easy to miss: nothing may quietly join the replica
// without a decision recorded above.
func TestNothingIsOffloadedWithoutBeingDeclared(t *testing.T) {
	var undeclared []string
	for _, name := range adminSourceFiles(t) {
		if _, ok := offloadedToReplica[name]; ok {
			continue
		}
		if strings.Contains(readAdminFile(t, name), ".Reader()") {
			undeclared = append(undeclared, name)
		}
	}
	if len(undeclared) > 0 {
		t.Errorf("%d file(s) read from the replica without being declared in offloadedToReplica:\n  %s\n"+
			"Add each with the reason its queries tolerate replication lag, or move them back to db.Pool.",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}
}

func sortedOffloaded() []string {
	out := make([]string, 0, len(offloadedToReplica))
	for k := range offloadedToReplica {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The census, and what makes this task finishable: EVERY file in the package
// that reads must be in exactly one of the two maps. Not only the read-only
// ones -- a file that also writes still needs a decision. It is nearly always
// the same decision, and writing it down is what stops the next person
// re-deriving it.
//
// A file in neither map is an undecided file, and an undecided file is how the
// next person ends up guessing.
func TestEveryFileWithReadsIsDecided(t *testing.T) {
	readCall := regexp.MustCompile(`\.(Reader\(\)|Pool)\.(Query|QueryRow)\(`)

	var undecided, both []string
	for _, name := range adminSourceFiles(t) {
		src := readAdminFile(t, name)
		if !readCall.MatchString(src) {
			continue
		}
		_, offloaded := offloadedToReplica[name]
		_, primary := stayOnPrimary[name]
		switch {
		case offloaded && primary:
			both = append(both, name)
		case !offloaded && !primary:
			undecided = append(undecided, name)
		}
	}
	if len(both) > 0 {
		t.Errorf("%d file(s) are in BOTH maps: %s", len(both), strings.Join(both, ", "))
	}
	if len(undecided) > 0 {
		t.Errorf("%d file(s) with reads are in neither map:\n  %s\n"+
			"Every read in this package is a decision. Add the file to offloadedToReplica with the reason its "+
			"queries tolerate lag, or to stayOnPrimary with the reason they do not.",
			len(undecided), strings.Join(undecided, "\n  "))
	}
}

// And the files that must stay put have to actually stay put.
func TestStayOnPrimaryFilesDoNotUseTheReplica(t *testing.T) {
	for name, reason := range stayOnPrimary {
		if len(strings.TrimSpace(reason)) < 30 {
			t.Errorf("%s: the reason for staying on the primary is missing or too thin (%q)", name, reason)
		}
		if strings.Contains(readAdminFile(t, name), ".Reader()") {
			t.Errorf("%s is declared read-after-write critical but reads from the replica: %s", name, reason)
		}
	}
}
