package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
	// took everything on the other side of it.
	//
	// A FUNCTION-LEVEL CENSUS WAS THE OBVIOUS NEXT STEP, AND MEASURING IT
	// KILLED IT. These files hold 132 functions that read and never write,
	// carrying 194 queries -- which looks like the remaining opportunity until
	// you read the names: handleListAIAgents, handleGetAttestationCampaign,
	// handleListRecommendations. Those are precisely the read-after-write
	// reads. The write is not in the same function; it is in handleCreateX, and
	// the relationship is the console's create-then-refetch, which spans two
	// handlers. So "this function does not write" licenses exactly the moves
	// that must not be made.
	//
	// The criterion is semantic, not structural: it is about what the SCREEN
	// does, and no shape of the Go source can decide it. What is genuinely left
	// -- handlers over historical aggregates nobody has just written, like
	// ispm GetPostureTrends or mfa_management MFAEnrollmentStats -- has to be
	// decided one screen at a time, against the console.
	//
	// That is where this comment used to stop, with "more machinery would not
	// help". It was half right. More machinery over the GO source would not
	// help. Machinery over the CONSOLE does, because "is this tile refetched
	// after a mutation" has a mechanical answer in a TanStack Query
	// application: it is refetched iff some mutation invalidates its key. The
	// offloadedHandlers tier below is that answer, per handler, with the whole
	// chain from query key to route to handler pinned so the argument cannot
	// go stale without a test going red.
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
	"ispm.go":                    "posture findings and rules: dismiss and remediate write, then the list refetches. The trend chart is the exception and has moved on its own, as offloadedHandlers records",
	"mfa_management.go":          "MFA policy CRUD. The policy decides whether a factor is required, so it belongs with the security-critical reads this package already keeps on the primary (see settings_repository.go). The enrolment-stats tile is the exception and has moved on its own, as offloadedHandlers records",
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
	declaredPerHandler := map[string]bool{}
	for _, h := range offloadedHandlers {
		declaredPerHandler[h.file] = true
	}

	var undeclared []string
	for _, name := range adminSourceFiles(t) {
		if _, ok := offloadedToReplica[name]; ok {
			continue
		}
		// A file with a declared handler is accounted for one handler at a
		// time by TestStayOnPrimaryFilesDoNotUseTheReplica, which counts every
		// .Reader() in the file against the declared bodies -- so an extra one
		// added elsewhere in the file is still caught.
		if declaredPerHandler[name] {
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

// And the files that must stay put have to actually stay put -- except for the
// handlers declared one at a time in offloadedHandlers. Counting rather than
// forbidding is what keeps the exception honest: a SECOND query in the same
// file quietly switched to the replica raises the file's count above the
// declared bodies' and fails here, even though the file is "already allowed".
func TestStayOnPrimaryFilesDoNotUseTheReplica(t *testing.T) {
	for name, reason := range stayOnPrimary {
		if len(strings.TrimSpace(reason)) < 30 {
			t.Errorf("%s: the reason for staying on the primary is missing or too thin (%q)", name, reason)
		}
		inFile := strings.Count(readAdminFile(t, name), ".Reader()")
		if inFile == 0 {
			continue
		}
		declared := 0
		for _, h := range offloadedHandlers {
			if h.file == name {
				declared += strings.Count(adminFuncBody(t, h.file, h.fn), ".Reader()")
			}
		}
		if inFile > declared {
			t.Errorf("%s is declared read-after-write critical and reads from the replica in %d place(s), but only %d sit inside a handler declared in offloadedHandlers.\nEvery offload inside a file that stays on the primary is declared one handler at a time, with the console evidence that nothing refetches it. The file's reason: %s",
				name, inFile, declared, reason)
		}
	}
}

// THE FINER GRAIN: ONE HANDLER MOVED OUT OF A FILE THAT STAYS.
//
// The comment above says the remaining opportunity is semantic and that no
// shape of the Go source can decide it. Both halves of that are still true.
// What was wrong was the conclusion drawn from them -- that the decision
// therefore needs a person looking at a screen, and so cannot be pinned here.
//
// It can, because the screen is IN THIS REPOSITORY. web/admin-console is a
// TanStack Query application, and in one of those a tile is refetched after a
// mutation if and only if some mutation invalidates its query key. That is not
// a heuristic about Go source, it is the console's own definition of
// read-after-write, and it is greppable. So a handler may serve the replica
// when its query key is never invalidated by anything: no mutation on its
// screen refetches it, therefore nothing can observe the lag.
//
// The guards below hold the whole chain, because any link breaking would make
// the claim false: console query key -> the URL its queryFn fetches -> the
// route registration in service.go -> the handler -> the replica. A console
// change that starts invalidating one of these keys turns this test red, in
// CI, in the same repository as the change. That is the property the file-level
// census could not have: the decision is re-checked by machine every time the
// thing it depends on moves.
//
// Note on prefix matching: TanStack invalidates by key PREFIX, so
// ['mfa-policies'] also invalidates ['mfa-policies', page]. Both keys declared
// here are single-element, so the only prefix of either is the empty key --
// invalidateQueries() with no arguments, which is handled separately below.

// offloadedHandler is one handler that reads from the replica inside a file
// that otherwise stays on the primary.
type offloadedHandler struct {
	file     string // the file in internal/admin that defines it
	fn       string // the handler's name
	route    string // the URL the console fetches, exactly as the console spells it
	queryKey string // the TanStack Query key the console stores the answer under
	reason   string // why nothing can observe replication lag here
}

var offloadedHandlers = []offloadedHandler{
	{
		file:     "ispm.go",
		fn:       "handleGetPostureTrends",
		route:    "/api/v1/ispm/trends",
		queryKey: "ispm-trends",
		reason: "ninety days of daily posture snapshots, drawn as a chart. The scan that writes today's row " +
			"invalidates ['ispm-score'] and ['ispm-findings'] and NOT this key, so the chart is not refetched " +
			"after a scan at all -- a second of replication lag is invisible next to a staleness that already " +
			"lasts until the page is remounted. If a later change makes the scan refresh the chart, " +
			"TestOffloadedHandlerKeysAreNeverInvalidated fails and this decision is made again",
	},
	{
		file:     "mfa_management.go",
		fn:       "handleMFAEnrollmentStats",
		route:    "/api/v1/mfa/enrollment-stats",
		queryKey: "mfa-enrollment-stats",
		reason: "how many users have each factor enrolled, counted across the tenant. The MFA screen writes " +
			"POLICIES, never enrolments -- an enrolment is written by the user themselves in the self-service " +
			"flow, in another service, minutes to days earlier -- so the three mutations on this screen all " +
			"invalidate ['mfa-policies'] and none can move this tile. The one admin-plane write that does touch " +
			"mfa_* tables is the DSAR erasure in privacy.go, on a different screen with different keys",
	},
}

// adminFuncBody returns the source of one function's body, braces included.
// go/parser rather than brace counting: the bodies here hold backquoted SQL and
// gin.H literals, and a guard that is approximate about where a function ends
// is a guard that can be argued with.
func adminFuncBody(t *testing.T, file, fn string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filepath.Clean(file), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	src := readAdminFile(t, file)
	for _, d := range parsed.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		return src[fset.Position(fd.Body.Pos()).Offset:fset.Position(fd.Body.End()).Offset]
	}
	t.Fatalf("offloadedHandlers names %s.%s, which this package does not define", file, fn)
	return ""
}

// Every declared handler must exist, sit in a file the census keeps on the
// primary, and carry a reason. The reason bar is higher here than at file
// level: these are the subtle ones, kept by a fact about another language's
// source, and a thin reason would not survive the next reader.
func TestOffloadedHandlersAreDeclaredCompletely(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range offloadedHandlers {
		if _, ok := stayOnPrimary[h.file]; !ok {
			t.Errorf("%s.%s: this tier is for a handler inside a file that STAYS on the primary, and %s is not in stayOnPrimary. If the whole file has moved, declare the file in offloadedToReplica instead",
				h.file, h.fn, h.file)
		}
		if _, ok := offloadedToReplica[h.file]; ok {
			t.Errorf("%s is declared offloaded as a whole file AND handler by handler; pick one", h.file)
		}
		if len(strings.TrimSpace(h.reason)) < 120 {
			t.Errorf("%s.%s: the reason is too thin (%d chars). Say which mutations exist on this screen and why none of them refetches this tile",
				h.file, h.fn, len(strings.TrimSpace(h.reason)))
		}
		if key := h.file + "." + h.fn; seen[key] {
			t.Errorf("%s is declared twice", key)
		} else {
			seen[key] = true
		}
		adminFuncBody(t, h.file, h.fn) // fails if the handler is gone or renamed
	}
	if len(offloadedHandlers) == 0 {
		t.Fatal("offloadedHandlers is empty; every test in this tier would pass vacuously")
	}
}

// The handler itself must have finished the move: replica only, and no write.
func TestOffloadedHandlerBodiesUseOnlyTheReplica(t *testing.T) {
	for _, h := range offloadedHandlers {
		body := adminFuncBody(t, h.file, h.fn)

		if !strings.Contains(body, ".Reader().Query") {
			t.Errorf("%s.%s is declared offloaded but holds no replica query", h.file, h.fn)
		}
		if strings.Contains(body, "db.Pool") {
			t.Errorf("%s.%s is declared offloaded but still queries db.Pool (the primary)", h.file, h.fn)
		}
		if m := writeCalls.FindString(body); m != "" {
			t.Errorf("%s.%s is declared offloaded but calls %s: a write through Reader() is refused by the server with SQLSTATE 25006, in production rather than here",
				h.file, h.fn, strings.Trim(m, ".("))
		}
	}
}

// The chain from the console to the handler. A route that moved, a handler
// renamed in service.go, or a key the console no longer uses would each leave
// the reason above describing a screen that no longer exists.
func TestOffloadedHandlersAreWiredToTheKeyTheyClaim(t *testing.T) {
	routes := readAdminFile(t, "service.go")
	console := consoleSources(t)

	for _, h := range offloadedHandlers {
		serverPath := strings.TrimPrefix(h.route, "/api/v1")
		registration := regexp.MustCompile(`"` + regexp.QuoteMeta(serverPath) + `",\s*svc\.` + regexp.QuoteMeta(h.fn) + `\b`)
		if !registration.MatchString(routes) {
			t.Errorf("%s.%s: service.go does not register %q to this handler, so the console evidence for %q is about some other endpoint",
				h.file, h.fn, serverPath, h.queryKey)
		}

		declaration := regexp.MustCompile(`queryKey:\s*\[\s*'` + regexp.QuoteMeta(h.queryKey) + `'\s*\]`)
		var declaredIn []string
		for path, src := range console {
			if declaration.MatchString(src) {
				declaredIn = append(declaredIn, path)
			}
		}
		if len(declaredIn) != 1 {
			t.Errorf("%s.%s: the console declares queryKey ['%s'] in %d place(s) %v; this tier's argument is about ONE screen and needs exactly one",
				h.file, h.fn, h.queryKey, len(declaredIn), declaredIn)
			continue
		}
		if !strings.Contains(console[declaredIn[0]], h.route) {
			t.Errorf("%s.%s: %s declares ['%s'] but does not fetch %q; the key and the route have drifted apart",
				h.file, h.fn, declaredIn[0], h.queryKey, h.route)
		}
	}
}

// AND THE ONE THAT DOES THE REAL WORK. Read-after-write on these screens means
// "a mutation invalidates this key". None may.
func TestOffloadedHandlerKeysAreNeverInvalidated(t *testing.T) {
	console := consoleSources(t)

	for path, src := range console {
		for _, args := range invalidateQueryArgs(src) {
			rel := consoleRelPath(path)
			if strings.TrimSpace(args) == "" {
				if _, allowed := blanketInvalidations[rel]; !allowed {
					t.Errorf("%s calls invalidateQueries() with no arguments, which refetches EVERY key including the ones offloaded to the replica. Either narrow it or record here why a blanket refetch is not a read-after-write", rel)
				}
				continue
			}
			for _, h := range offloadedHandlers {
				if strings.Contains(args, "'"+h.queryKey+"'") || strings.Contains(args, `"`+h.queryKey+`"`) {
					t.Errorf("%s invalidates ['%s'], so the console DOES refetch it after a mutation -- it is a read-after-write and %s.%s must go back to db.Pool.\nThe reason recorded for the offload was: %s",
						rel, h.queryKey, h.file, h.fn, h.reason)
				}
			}
		}
	}
}

// blanketInvalidations records the invalidateQueries() calls that take no
// arguments, and why each is not a read-after-write for the offloaded tiles.
// An undeclared one fails the test above, because a blanket refetch is exactly
// the thing that would quietly turn every offloaded tile into one.
var blanketInvalidations = map[string]string{
	"components/tenant-selector.tsx": "switching tenant refetches everything, because every answer on screen belongs to the organization that was selected. That is a context change, not a read-after-write: the rows the new tenant's chart and enrolment counts read were written by that tenant long before the switch, and the replica has had them for just as long",
}

func TestBlanketInvalidationsStillExist(t *testing.T) {
	console := consoleSources(t)
	for rel, reason := range blanketInvalidations {
		if len(strings.TrimSpace(reason)) < 60 {
			t.Errorf("%s: the reason a blanket refetch is safe here is too thin (%q)", rel, reason)
		}
		src, ok := console[filepath.Join(adminConsoleSrc, filepath.FromSlash(rel))]
		if !ok {
			t.Errorf("blanketInvalidations names %s, which is not in the console any more; drop the entry", rel)
			continue
		}
		var bare bool
		for _, args := range invalidateQueryArgs(src) {
			if strings.TrimSpace(args) == "" {
				bare = true
			}
		}
		if !bare {
			t.Errorf("%s no longer calls invalidateQueries() with no arguments; drop the entry so the next blanket call is caught", rel)
		}
	}
}

const adminConsoleSrc = "../../web/admin-console/src"

func consoleRelPath(path string) string {
	rel, err := filepath.Rel(adminConsoleSrc, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func consoleSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(adminConsoleSrc, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (filepath.Ext(path) != ".ts" && filepath.Ext(path) != ".tsx") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", adminConsoleSrc, err)
	}
	// Vacuity guard, and the one that matters most in this tier: if the console
	// moved or the relative path broke, every assertion about what it does not
	// invalidate would pass over an empty map.
	if len(out) < 200 {
		t.Fatalf("only %d TypeScript sources under %s; the console evidence this tier rests on is not being read", len(out), adminConsoleSrc)
	}
	return out
}

// invalidateQueryArgs returns the argument text of every invalidateQueries call
// in src, with the outermost parentheses stripped. Brace-balanced rather than
// line-based, because the calls are written across lines as often as not.
func invalidateQueryArgs(src string) []string {
	const marker = "invalidateQueries("
	var out []string
	for i := 0; ; {
		j := strings.Index(src[i:], marker)
		if j < 0 {
			return out
		}
		start := i + j + len(marker)
		depth, k := 1, start
		for ; k < len(src) && depth > 0; k++ {
			switch src[k] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			}
		}
		if k-1 < start {
			return out // unterminated call: nothing to report on
		}
		out = append(out, src[start:k-1])
		i = k
	}
}
