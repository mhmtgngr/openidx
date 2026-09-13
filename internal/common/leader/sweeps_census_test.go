package leader

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY REPLICA RUNS EVERY TICKER, AND THAT IS THE DEFECT THIS CENSUS EXISTS
// FOR.
//
// A background sweep started in a service's main runs in every pod of that
// Deployment. access-service ships at two replicas and autoscales to eight;
// audit-service and oauth-service at three, to ten and twelve. So a sweep with
// no coordination does its work once per replica, and the poll interval an
// operator configured is silently multiplied by a number they did not choose.
//
// Twelve sweeps in this tree already run through leader.RunPeriodic. Three did
// not, and nothing about them was special:
//
//   - the EDR ingestion poller called the customer's CrowdStrike / Intune /
//     Jamf tenant once per replica, on the customer's own rate limit, and each
//     sync writes posture results the Ziti enforcement path acts on;
//   - the Guacamole external audit sync inserted each remote session with a
//     FRESH uuid primary key, so its ON CONFLICT DO NOTHING could never fire
//     for a logically duplicate event -- two replicas wrote two audit rows for
//     one recorded session, and on a compliance product that is a wrong answer,
//     not waste;
//   - the Elasticsearch reconciler indexed the same five hundred documents once
//     per replica, on the highest-volume path the product has, at precisely the
//     moment ES is already behind.
//
// All three are leader-gated now. This census is what stops the fourth: a new
// ticker in a file nobody listed fails here, and the author has to say which of
// the three coordination answers applies.
//
// THE THREE ANSWERS:
//
//	coordLeader     gated by leader.RunPeriodic / IsLeaderForTick -- one replica
//	                per interval, cluster-wide.
//	coordClaim      claims its work in the database (FOR UPDATE SKIP LOCKED), so
//	                any number of replicas is safe and none duplicates.
//	coordAdvisory   takes a Postgres advisory lock over the unit of work, which
//	                is the right answer when the work is not a set of claimable
//	                ROWS but a sequence only one writer may extend.
//	coordPerProcess legitimately once per process: it reports this pod's own
//	                metrics, refreshes this pod's own cache, or serves one
//	                connection. Gating these would be the bug.
//	coordUndecided  not yet audited. Counted and named, never silent -- the
//	                same shape as orgscope's needsScoping register, and for the
//	                same reason: an unreviewed entry that reads as reviewed is
//	                worse than an open question.
const (
	coordLeader     = "leader"
	coordClaim      = "claim"
	coordAdvisory   = "advisory-lock"
	coordPerProcess = "per-process"
	coordUndecided  = "undecided"
)

type sweep struct {
	how    string
	reason string
}

var tickerCensus = map[string]sweep{
	// -- Claims its work in the database; safe at any replica count.
	"internal/access/network_grant_worker.go": {coordClaim,
		"claims grants with FOR UPDATE SKIP LOCKED, so a row another replica holds is invisible to this one"},
	"internal/access/network_revocation_worker.go": {coordClaim,
		"claims revocations with FOR UPDATE SKIP LOCKED"},
	"internal/oauth/ssf_transmitter.go": {coordClaim,
		"claims SSF outbox rows with FOR UPDATE SKIP LOCKED"},
	"internal/provisioning/outbound_worker.go": {coordClaim,
		"claims queue items with FOR UPDATE SKIP LOCKED and requeues its own abandoned claims"},
	"internal/audit/chain.go": {coordAdvisory,
		"SealOrg takes pg_advisory_xact_lock per org: the tamper-evident chain is a sequence only one writer may extend, so a row claim would be the wrong shape"},
	"internal/audit/siem_forwarder.go": {coordClaim,
		"holds the singleton forward cursor with FOR UPDATE SKIP LOCKED for the whole batch; the SIEM dedupes on event id but bills by ingest volume, so steady-state duplication costs the customer"},
	"internal/audit/usage_metering.go": {coordClaim,
		"holds the singleton billing cursor row with FOR UPDATE SKIP LOCKED for the whole batch; the rollup is an increment, so a second replica must not read the same cursor"},

	// -- Once per process on purpose. Gating any of these would be the defect.
	"internal/common/leader/leader.go": {coordPerProcess,
		"this IS the gate: RunPeriodic's own ticker drives the per-tick leader election"},
	"internal/common/shutdown/graceful.go": {coordPerProcess,
		"watches THIS process's health while it drains; a leader draining on another pod's behalf is meaningless"},
	"internal/metrics/prometheus.go": {coordPerProcess,
		"each replica reports its own metrics; gating would leave every non-leader pod reporting nothing"},
	"internal/metrics/db.go": {coordPerProcess,
		"samples THIS process's pool gauges; the numbers are per-pod by definition"},
	"internal/audit/stream.go": {coordPerProcess,
		"websocket keepalive for one client connection, not a sweep"},
	"internal/oauth/signer.go": {coordPerProcess,
		"refreshes this process's signing-key cache; every pod needs current keys, not just the leader"},
	"cmd/openidx/commands/status.go": {coordPerProcess,
		"the CLI's --watch refresh loop, one per invocation of a command a human is running"},

	// -- Not yet audited. Each needs the same question answered: at eight
	// replicas, does this do its work eight times, and does that matter?
	"internal/access/agent_api.go": {coordUndecided,
		"agent-facing ticker: does a pass push anything to an agent, or only read? a push repeated per replica reaches the device that many times"},
	"internal/access/guacamole_users.go": {coordUndecided,
		"reconciles users into Guacamole: is the upsert keyed so two replicas converge, or can both create the same account?"},
	"internal/access/lifecycle_sweep.go": {coordUndecided,
		"lifecycle transitions: are they idempotent state changes, or do they emit a notification or audit row per pass?"},
	"internal/access/posture.go": {coordUndecided,
		"ages posture to failing: an idempotent UPDATE is safe at N, but a revocation or notification triggered by the transition is not"},
	"internal/access/remote_support_api.go": {coordUndecided,
		"25s ticker: is it per live support session (per-process, fine) or an install-wide sweep?"},
	"internal/access/remote_support_retention.go": {coordUndecided,
		"seals and deletes recordings: deletion is idempotent, but sealing is a chain-shaped write and two sealers may not both extend it"},
	"internal/access/ziti_fabric.go": {coordUndecided,
		"polls fabric health: if it only reads and reports, per-process is right; if it writes a shared health row, it is not"},
	"internal/access/ziti_hardening.go": {coordUndecided,
		"hourly hardening pass against the Ziti controller: N replicas is N times the controller API calls even if each pass converges"},
	"internal/access/ziti_reconciler.go": {coordUndecided,
		"READ, NOT MEASURED. runLocked holds a process-local mutex, which reads like coordination and coordinates " +
			"nothing across replicas. ensureService is check-then-act (GetServiceByName, then create), so two replicas " +
			"converging a NEW route can both see 'missing' and both create it; if the controller enforces unique " +
			"service names the loser gets a conflict, marks the route 'error' and self-heals on the next tick -- noisy " +
			"rather than corrupting, but the noise looks like a real failure. Separately, every replica reconciles " +
			"every route every tick, so a large install multiplies the controller's API load by the replica count. " +
			"The likely fix gates the TICKER path only and leaves Enqueue() ungated: a replica that just changed " +
			"something should converge it immediately, and only the periodic sweep needs one owner. NOT done here " +
			"because there is no Ziti controller to measure against, and a claim about this subsystem that is read " +
			"rather than measured is the kind this register exists to keep out of the 'decided' column."},
	"internal/access/ziti_user_sync.go": {coordUndecided,
		"syncs users into Ziti: same question as the reconciler, plus whether enrolment tokens are minted per pass"},
	"internal/identity/sms_config_watcher.go": {coordUndecided,
		"probably per-process (it refreshes this pod's provider cache) -- confirm it writes nothing shared, then record it as such"},
}

// TestEveryTickerIsAccountedFor is derived rather than listed: it finds the
// tickers itself, so a new one cannot be added without a decision. The three
// that were wrong looked exactly like the twelve that were right.
func TestEveryTickerIsAccountedFor(t *testing.T) {
	found := tickerFiles(t)
	if len(found) < 15 {
		t.Fatalf("found only %d files with a ticker (%v) -- the detector is not seeing the tree", len(found), found)
	}

	var unlisted []string
	for _, f := range found {
		if _, ok := tickerCensus[f]; !ok {
			unlisted = append(unlisted, f)
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) != 0 {
		t.Errorf("file(s) starting a ticker that the census does not name: %s\n\n"+
			"Every replica runs every ticker. Decide which answer applies -- leader.RunPeriodic (one "+
			"replica per interval), a FOR UPDATE SKIP LOCKED claim, a pg_advisory lock over the unit "+
			"of work, or genuinely per-process -- and add the file to tickerCensus with the reason.",
			strings.Join(unlisted, ", "))
	}

	// And the reverse: an entry for a file that no longer has a ticker is a
	// decision nobody rechecks.
	inTree := map[string]bool{}
	for _, f := range found {
		inTree[f] = true
	}
	for f := range tickerCensus {
		if !inTree[f] {
			t.Errorf("tickerCensus names %q, which no longer starts a ticker -- drop the entry", f)
		}
	}
}

func TestEveryCensusEntryHasAValidAnswerAndAReason(t *testing.T) {
	valid := map[string]bool{coordLeader: true, coordClaim: true, coordAdvisory: true,
		coordPerProcess: true, coordUndecided: true}
	for f, s := range tickerCensus {
		if !valid[s.how] {
			t.Errorf("%s: %q is not one of leader/claim/per-process/undecided", f, s.how)
		}
		if len(strings.TrimSpace(s.reason)) < 15 {
			t.Errorf("%s: no real reason -- say why this coordination is the right one", f)
		}
	}
}

// A claim entry has to actually claim, and a leader entry has to actually gate.
// Otherwise the census records an intention rather than the code.
func TestClaimAndLeaderEntriesAreBackedByTheSource(t *testing.T) {
	root := repoRoot(t)
	for f, s := range tickerCensus {
		body, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(body)
		switch s.how {
		case coordClaim:
			if !strings.Contains(src, "SKIP LOCKED") {
				t.Errorf("%s is recorded as claim-based but contains no FOR UPDATE SKIP LOCKED", f)
			}
		case coordAdvisory:
			if !strings.Contains(src, "pg_advisory") {
				t.Errorf("%s is recorded as advisory-locked but takes no pg_advisory lock", f)
			}
		case coordLeader:
			if !strings.Contains(src, "leader.RunPeriodic") && !strings.Contains(src, "leader.IsLeaderForTick") &&
				!strings.Contains(src, "RunPeriodic(") {
				t.Errorf("%s is recorded as leader-gated but never calls the gate", f)
			}
		}
	}
}

// The undecided list is a backlog, and a backlog that grows quietly is the
// register becoming the place drift hides. This pins its size: shrinking it is
// free, growing it takes an edit here and a sentence about why.
func TestTheUndecidedBacklogDoesNotGrow(t *testing.T) {
	const known = 11
	n := 0
	for _, s := range tickerCensus {
		if s.how == coordUndecided {
			n++
		}
	}
	if n > known {
		t.Errorf("the undecided ticker backlog grew to %d (was %d). A new sweep must be decided, not parked.", n, known)
	}
	if n < known {
		t.Errorf("the undecided backlog is down to %d from %d -- good; lower the constant so it cannot drift back up.", n, known)
	}
}

func tickerFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(body), "time.NewTicker") {
				rel, _ := filepath.Rel(root, path)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(out)
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root (no go.mod above the test's directory)")
	return ""
}
