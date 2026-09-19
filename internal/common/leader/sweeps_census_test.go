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
//	coordIdempotent needs no coordination: every write is a DELETE or an
//	                `UPDATE ... WHERE <still to do>`, so a second replica's
//	                statement matches nothing. Under READ COMMITTED the second
//	                updater blocks on the row lock and then re-evaluates its
//	                predicate against the committed row -- the database does the
//	                coordinating. This is the answer that rests most on its
//	                reason, so it is the one that must be MEASURED: see
//	                internal/access/lifecycle_sweep_testdb_test.go, where eight
//	                concurrent sweeps are shown to land on the same settled
//	                state as one.
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
	coordIdempotent = "idempotent"
	coordPerProcess = "per-process"
	coordUndecided  = "undecided"
)

type sweep struct {
	how    string
	reason string
	// fn names the sweep's own function (or functions, comma-separated, when
	// one ticker drives more than one), and an `idempotent` entry must set
	// it. The first version of this guard scanned the whole FILE for the two
	// shapes that break idempotence, which worked for a 145-line file holding
	// nothing but its sweep and fired a false positive on the second entry
	// tried: posture.go is 1054 lines with five unrelated INSERTs. What the
	// answer is about is the sweep, so that is what gets read.
	fn string
}

var tickerCensus = map[string]sweep{
	// -- Claims its work in the database; safe at any replica count.
	"internal/access/network_grant_worker.go":      {how: coordClaim, reason: "claims grants with FOR UPDATE SKIP LOCKED, so a row another replica holds is invisible to this one"},
	"internal/access/network_revocation_worker.go": {how: coordClaim, reason: "claims revocations with FOR UPDATE SKIP LOCKED"},
	"internal/oauth/ssf_transmitter.go":            {how: coordClaim, reason: "claims SSF outbox rows with FOR UPDATE SKIP LOCKED"},
	"internal/oauth/ssf_signal_drain.go":           {how: coordClaim, reason: "claims ssf_pending_events rows with FOR UPDATE SKIP LOCKED and hands back a claim stalled past its grace; the row lock is the coordination, any number of replicas drain safely, and a leader would add an availability gap for an ordering guarantee nobody asked for"},
	"internal/oauth/backchannel_logout_drain.go":   {how: coordClaim, reason: "claims backchannel_logout_pending rows with FOR UPDATE SKIP LOCKED and hands back a claim stalled past its grace, the SSF signal drainer's shape for the SSF signal drainer's reason; a relying party told twice about one ended session is required by Back-Channel Logout 1.0 to treat the repeated jti as handled, so at-least-once is the safe direction"},
	"internal/provisioning/outbound_worker.go":     {how: coordClaim, reason: "claims queue items with FOR UPDATE SKIP LOCKED and requeues its own abandoned claims"},
	"internal/audit/chain.go":                      {how: coordAdvisory, reason: "SealOrg takes pg_advisory_xact_lock per org: the tamper-evident chain is a sequence only one writer may extend, so a row claim would be the wrong shape"},
	"internal/audit/siem_forwarder.go":             {how: coordClaim, reason: "holds the singleton forward cursor with FOR UPDATE SKIP LOCKED for the whole batch; the SIEM dedupes on event id but bills by ingest volume, so steady-state duplication costs the customer"},
	"internal/audit/usage_metering.go":             {how: coordClaim, reason: "holds the singleton billing cursor row with FOR UPDATE SKIP LOCKED for the whole batch; the rollup is an increment, so a second replica must not read the same cursor"},

	// -- Safe to repeat, so safe at any replica count.
	"internal/access/lifecycle_sweep.go": {how: coordIdempotent, reason: "MEASURED (lifecycle_sweep_testdb_test.go): every write is a DELETE or an UPDATE filtered on still-active " +
		"rows, it emits no notification and inserts nothing, and eight concurrent sweeps land on the same settled " +
		"state as one -- a further pass after them changes nothing", fn: "runLifecycleEnforcement"},
	"internal/access/posture.go": {how: coordIdempotent, reason: "one statement: DELETE FROM device_posture_results WHERE expires_at < NOW(). Idempotent by " +
		"construction -- the second replica's DELETE matches rows the first already removed, so it matches nothing. " +
		"It also DECIDES nothing, which is the part worth recording: EvaluateIdentityPosture fails a check whose " +
		"result has expired and fails a check with no result at all in the same way, so removing the row cannot move " +
		"a device between allowed and denied. The sweep reclaims storage; it is not the thing that ages a device to " +
		"failing, and there is no revocation or notification for a second replica to fire twice.",
		fn: "cleanExpiredPostureResults"},

	"internal/access/guacamole_users.go": {how: coordIdempotent, reason: "MEASURED (guac_grant_sweep_testdb_test.go). One ticker, two sweeps, and BOTH now clear their own " +
		"work. The deprovision sweep deletes the broker account and then the mapping row, and a second replica's " +
		"delete of an account already gone is the tolerated 404, so the row goes either way and the pair " +
		"converges. The stale-grant sweep did NOT clear its work: it revoked the READ an ended session left " +
		"behind and wrote nothing, so the same rows matched on every tick forever -- invisible because " +
		"re-revoking an absent grant is also a tolerated 404, i.e. the sweep looked like it worked because it " +
		"never failed. The cost that mattered was not the wasted calls but the LIMIT 200 with no progress: past " +
		"two hundred matching rows it revisited an arbitrary two hundred and the rest might never be reached, " +
		"and the grants most needing revocation are exactly the ones that sit behind it. v193 adds " +
		"guac_revoked_at, written only when the broker CONFIRMS, so the backlog drains and the second pass " +
		"calls the broker zero times",
		fn: "sweepStaleGuacGrants,sweepDeprovisionGuacUsers"},

	"internal/access/remote_support_api.go": {how: coordIdempotent, reason: "MEASURED (remote_support_janitor_testdb_test.go). The janitor sets status='expired' on rows WHERE " +
		"status IN ('pending','active'), which is the shape the answer rests on: the write makes the predicate " +
		"false, so a second replica matches nothing. Eight concurrent janitors expire the two orphans once, " +
		"leave the session with recent activity alone, and land settled -- and the test digests the VALUES " +
		"rather than counting rows, because the failure mode here is a sweep re-applying itself and rewriting " +
		"ended_at with a fresh NOW() on every tick, which on a product that records support sessions for " +
		"compliance is a wrong answer to 'when did this end', not a wasted write. The file's OTHER ticker is " +
		"not a sweep: runPeer's is a per-websocket keepalive for one connected peer, per-process by " +
		"definition, and gating it would mean a leader holding another pod's websocket open",
		fn: "expireOrphanSessions"},

	"internal/access/agent_api.go": {how: coordIdempotent, reason: "MEASURED (grace_period_enforcer_testdb_test.go). The census question was whether a pass PUSHES " +
		"anything, and it does: every agent it suspends gets an agent.suspended row in the unified audit " +
		"stream, which is precisely the shape the Guacamole audit sync got wrong (one row per replica for one " +
		"recorded event). It is right here because the claim and the work are the SAME statement -- UPDATE ... " +
		"WHERE compliance_status = 'grace_period' ... RETURNING -- so a second replica blocks on the row lock, " +
		"re-evaluates against the committed row, gets nothing back and never reaches the insert. Eight " +
		"concurrent enforcers suspend two agents and announce each once. NOTE the guard reads this function " +
		"and not its callees, so the audit INSERT is invisible to it; what makes the insert safe is the " +
		"RETURNING above it, and that is what the measurement is of",
		fn: "enforceExpiredGracePeriods"},

	"internal/access/remote_support_retention.go": {how: coordIdempotent, reason: "MEASURED (guac_recording_double_seal_test.go, guac_seal_claim_testdb_test.go). Five sweeps on one " +
		"ticker; the census question guessed the sealer was a chain-shaped write, and it is worse than that. " +
		"sealOneGuacRecording REWRITES THE RECORDING IN PLACE and the candidate query claimed nothing, so two " +
		"replicas on one tick both sealed the same file and the second encrypted the first's ciphertext -- " +
		"recording_sha256 then held the digest of ciphertext, one decrypt pass returned ciphertext, and on a " +
		"product that records privileged sessions the evidence was gone with the row still reading 'sealed'. " +
		"The sweep's own comment had already named the same corruption for a crash between the rename and the " +
		"metadata write. Fixed by REFUSING ciphertext -- the probe decrypts the first frame, so AES-GCM " +
		"authenticates the answer rather than guessing from how the bytes look -- which makes the seal " +
		"idempotent by construction for every replica count and closes the crash path too. The announcement " +
		"half is a claim (recordGuacSeal). The purge sweeps were already self-clearing: each candidate query " +
		"filters on its own purged_at",
		fn: "sealGuacRecordings,sweepExpiredRecordings,sweepExpiredGuacRecordings"},

	"internal/access/ziti_user_sync.go": {how: coordIdempotent, reason: "PART MEASURED (ziti_user_sync_claim_testdb_test.go), PART READ, and the entry says which. The poller " +
		"is check-then-act across TWO systems: it selects ten users with no identity -- every replica selects " +
		"the same ten -- then asks the controller to create one and persists it. Nothing corrupts because two " +
		"unique constraints sit on the same name, one in each system: the controller rejects a duplicate " +
		"identity name (the loser adopts the winner's, which the create path already handles) and " +
		"ziti_identities.name is UNIQUE with name = the user id. The controller half is READ from its contract, " +
		"not measured -- there is no controller in reach, the same honesty ziti_reconciler.go gets. The DATABASE " +
		"half is measured, and it is where the visible defect was: the losing insert raised a unique violation " +
		"and the poller reported 'Auto-sync failed for user' once per replica per tick for a user that HAD been " +
		"synced, which is the kind of alarm that teaches people to ignore the channel. The insert is now the " +
		"claim (ON CONFLICT DO NOTHING). The deprovision half deletes by primary key after a 404-tolerant " +
		"controller delete, so a second replica's pass matches nothing",
		fn: "persistZitiIdentity,runDeprovisionSweep"},

	"internal/access/ziti_hardening.go": {how: coordIdempotent, reason: "MEASURED (ziti_cert_rotation_testdb_test.go). The hourly expiry monitor runs in every replica and " +
		"every replica lists the same expiring certificates, but the rotation has always CLAIMED: " +
		"`UPDATE ziti_certificates SET status='rotating' WHERE id=$1 AND status='active'` means exactly one " +
		"replica rotates and the rest stand down. What was wrong was what the rest then SAID -- " +
		"'Auto-rotation failed for certificate', at Error, about a certificate another replica was rotating " +
		"correctly. A certificate rotation is security-relevant, and an operator who watches it fail every hour " +
		"for a rotation that succeeded learns to skip the line: the same defect the user-sync poller had. " +
		"Losing the claim is now its own error and the monitor logs it as what it is. The remaining per-replica " +
		"cost is the listing itself, once an hour",
		fn: "RotateCertificate"},

	// -- Once per process on purpose. Gating any of these would be the defect.
	"internal/common/leader/leader.go":     {how: coordPerProcess, reason: "this IS the gate: RunPeriodic's own ticker drives the per-tick leader election"},
	"internal/common/shutdown/graceful.go": {how: coordPerProcess, reason: "watches THIS process's health while it drains; a leader draining on another pod's behalf is meaningless"},
	"internal/metrics/prometheus.go":       {how: coordPerProcess, reason: "each replica reports its own metrics; gating would leave every non-leader pod reporting nothing"},
	"internal/metrics/db.go":               {how: coordPerProcess, reason: "samples THIS process's pool gauges; the numbers are per-pod by definition"},
	"internal/audit/stream.go":             {how: coordPerProcess, reason: "websocket keepalive for one client connection, not a sweep"},
	"internal/oauth/signer.go": {how: coordPerProcess, reason: "refreshes this process's signing-key cache, and gating it would be the defect: eleven of twelve " +
		"oauth-service replicas would serve a stale JWKS. READ TWICE, because the tick is not only a read -- it also " +
		"calls signingkeys.PruneExpired, a DELETE of retired keys past their grace, which is a predicate delete and " +
		"so costs nothing extra per replica. The audit found something else in the same function: the refresh ALSO " +
		"assigned s.privateKey / s.publicKey, which the SAML signing paths read on request goroutines -- an " +
		"unsynchronised write racing every SAML signature. Fixed (signer_race_testdb_test.go, measured with -race)"},
	"internal/identity/sms_config_watcher.go": {how: coordPerProcess, reason: "reads one system_settings row and writes NOTHING: the tick swaps this process's own SMS " +
		"provider and OTP settings, and its lastUpdatedAt high-water mark is a local variable in the watcher's own " +
		"goroutine. Gating it would be the defect -- a non-leader pod would keep sending codes through the provider " +
		"an administrator just replaced, for as long as it stays up"},
	"cmd/openidx/commands/status.go": {how: coordPerProcess, reason: "the CLI's --watch refresh loop, one per invocation of a command a human is running"},

	"internal/access/ziti_fabric.go": {how: coordLeader, reason: "MEASURED (ziti_fabric_metrics_testdb_test.go). The tick is two kinds of work and the census " +
		"question had both answers: the health check and the re-authentication are per-process and must run in " +
		"every replica (each pod holds its own SDK session, and a pod that skipped its own re-auth because " +
		"another was leader would stay disconnected), while the metrics it wrote are FABRIC facts -- routers " +
		"online, services and identities count -- so a row per replica was one fact written N times. Seven rows " +
		"a tick: at eight replicas the fabric overview's 50-row window fell from ~3.5 minutes of history to 26 " +
		"seconds of the same instant. The metric half is now gated per tick; eight racing replicas write seven " +
		"rows, and with the gate ignored they write fifty-six"},

	// -- Not yet audited. Each needs the same question answered: at eight
	// replicas, does this do its work eight times, and does that matter?
	"internal/access/ziti_reconciler.go": {how: coordUndecided, reason: "READ, NOT MEASURED. runLocked holds a process-local mutex, which reads like coordination and coordinates " +
		"nothing across replicas. ensureService is check-then-act (GetServiceByName, then create), so two replicas " +
		"converging a NEW route can both see 'missing' and both create it; if the controller enforces unique " +
		"service names the loser gets a conflict, marks the route 'error' and self-heals on the next tick -- noisy " +
		"rather than corrupting, but the noise looks like a real failure. Separately, every replica reconciles " +
		"every route every tick, so a large install multiplies the controller's API load by the replica count. " +
		"The likely fix gates the TICKER path only and leaves Enqueue() ungated: a replica that just changed " +
		"something should converge it immediately, and only the periodic sweep needs one owner. NOT done here " +
		"because there is no Ziti controller to measure against, and a claim about this subsystem that is read " +
		"rather than measured is the kind this register exists to keep out of the 'decided' column."},
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
		coordIdempotent: true, coordPerProcess: true, coordUndecided: true}
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
		case coordIdempotent:
			// No proof is available from the source, so this checks the two
			// shapes that were actually WRONG in this tree: an INSERT per
			// pass (the Guacamole audit sync wrote a duplicate row per
			// replica) and a read-modify-write increment (the metering
			// rollup billed a customer once per replica). Neither is proof
			// of idempotence; both catch its most common absence.
			//
			// Scoped to the sweep's own function: a file may hold plenty of
			// request-path writes that say nothing about its ticker.
			if s.fn == "" {
				t.Errorf("%s is recorded as idempotent without naming its function; "+
					"the answer is about the sweep, not the file", f)
				continue
			}
			for _, fn := range strings.Split(s.fn, ",") {
				fn = strings.TrimSpace(fn)
				body, ok := sweepFunctionBody(t, root, f, src, fn)
				if !ok {
					t.Errorf("%s names %s(), which is in neither the file nor its package", f, fn)
					continue
				}
				// An INSERT is the shape that was actually wrong here (the
				// Guacamole audit sync wrote a row per replica), unless it
				// CLAIMS: `ON CONFLICT (<target>) DO NOTHING` makes the insert
				// idempotent, because the second replica's row is refused by a
				// key rather than written.
				//
				// THE CONFLICT TARGET HAS TO BE NAMED, and the Guacamole defect
				// is why. That sync also said ON CONFLICT DO NOTHING -- and
				// could never fire it, because the row it inserted carried a
				// freshly generated uuid primary key, so no two attempts ever
				// conflicted. A targetless ON CONFLICT is a statement about
				// whatever unique index happens to exist; a named one is a
				// statement about the key the claim rests on.
				if strings.Contains(body, "INSERT INTO") && !insertClaims(body) {
					t.Errorf("%s: %s() is recorded as idempotent but INSERTs without claiming; an insert per pass "+
						"is a row per replica. An `ON CONFLICT (<column>) DO NOTHING` naming the key it rests on "+
						"is a claim; a bare insert, or one whose conflict target is unnamed, is not", f, fn)
				}
				if strings.Contains(body, "+ 1") || strings.Contains(body, "+1 ") {
					t.Errorf("%s: %s() is recorded as idempotent but looks like it increments; "+
						"a read-modify-write is the shape that billed a customer once per replica", f, fn)
				}
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
	const known = 1
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

// insertClaims reports whether every INSERT in body carries a NAMED
// ON CONFLICT ... DO NOTHING, which is what turns an insert into a claim.
//
// Deliberately crude, and deliberately strict about the target: see the comment
// at the call site for the Guacamole sync, which satisfied a naive "does it say
// ON CONFLICT" check while inserting a fresh uuid primary key that could never
// collide.
func insertClaims(body string) bool {
	for _, chunk := range strings.Split(body, "INSERT INTO")[1:] {
		idx := strings.Index(chunk, "ON CONFLICT")
		if idx < 0 {
			return false
		}
		rest := strings.TrimSpace(chunk[idx+len("ON CONFLICT"):])
		// A named target: `(column)` or `ON CONSTRAINT name`.
		if !strings.HasPrefix(rest, "(") && !strings.HasPrefix(rest, "ON CONSTRAINT") {
			return false
		}
		if !strings.Contains(chunk[idx:], "DO NOTHING") {
			return false
		}
	}
	return true
}

// sweepFunctionBody finds fn for a census entry: in the entry's own file first,
// then anywhere in that file's package.
//
// THE PACKAGE FALLBACK IS NOT A LOOSENING, and the entry that forced it says
// why. remote_support_retention.go starts one ticker that drives five sweeps,
// and the one worth reading -- the recording sealer -- lives in a sibling file
// because it is a large subsystem of its own. The census keys on the file that
// starts the TICKER, which is the right key (that is where a new ticker
// appears), so a ticker whose work is split across a package would otherwise be
// undescribable: either the entry names a function the guard cannot find, or it
// names only the half that happens to share the file.
//
// The guard keeps what makes it a guard: the function must exist, and its body
// is what gets read. It just stops assuming a sweep and its ticker share a
// file.
func sweepFunctionBody(t *testing.T, root, entryFile, src, fn string) (string, bool) {
	t.Helper()
	if body, ok := functionBody(src, fn); ok {
		return body, true
	}
	dir := filepath.Join(root, filepath.Dir(entryFile))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sibling, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		if body, ok := functionBody(string(sibling), fn); ok {
			return body, true
		}
	}
	return "", false
}

// functionBody returns the source of fn, from its declaration to the next
// top-level func. Text rather than an AST walk on purpose: the check it feeds
// is a heuristic about two SQL shapes, and parsing would lend it a precision it
// does not have.
func functionBody(src, fn string) (string, bool) {
	marker := ") " + fn + "("
	i := strings.Index(src, marker)
	if i < 0 {
		if i = strings.Index(src, "func "+fn+"("); i < 0 {
			return "", false
		}
	}
	rest := src[i:]
	if j := strings.Index(rest[1:], "\nfunc "); j >= 0 {
		return rest[:j+1], true
	}
	return rest, true
}
