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

// The census that makes the next batch mechanical: a file with reads and no
// writes is a candidate, and every candidate must be in exactly one of the two
// maps. Anything that is in neither is an undecided file, and an undecided file
// is how the next person ends up guessing.
//
// Files that DO write are out of scope here: they cannot be offloaded wholesale
// anyway, and they move query by query when their turn comes.
func TestEveryReadOnlyFileIsDecided(t *testing.T) {
	readCall := regexp.MustCompile(`\.(Reader\(\)|Pool)\.(Query|QueryRow)\(`)
	writeCall := regexp.MustCompile(`\.Pool\.(Exec|Begin|CopyFrom|SendBatch)\(`)

	var undecided, both []string
	for _, name := range adminSourceFiles(t) {
		src := readAdminFile(t, name)
		if !readCall.MatchString(src) || writeCall.MatchString(src) {
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
		t.Errorf("%d read-only file(s) are in neither map:\n  %s\n"+
			"Each is a candidate for the replica. Add it to offloadedToReplica with the reason its queries "+
			"tolerate lag, or to stayOnPrimary with the reason they do not.",
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
