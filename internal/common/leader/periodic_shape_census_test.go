package leader

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// PERIODIC WORK FOUND BY SHAPE, BECAUSE THE OTHER TWO CENSUSES FIND IT BY NAME.
//
// There are two coordination censuses already and both are keyed on a spelling:
//
//   - the sweeps census in this package walks only files containing the string
//     "time.NewTicker", and classifies what it finds there;
//   - cmd's background-work census derives the Start<Name>( calls a main.go
//     makes, and requires each to reach a coordination answer.
//
// A loop that repeats on a timer without using either spelling is invisible to
// both, and one exists on this tree. internal/common/events.Relay.Run is the
// outbox poller: it loops forever, waits on `case <-time.After(PollInterval)`,
// and is started from cmd/event-relay as `go relay.Run(ctx)`. There is no
// ticker in its file, so the sweeps census never opens it; the entry point is
// not called Start-anything, so cmd's census never names it. Measured, both,
// on this tree.
//
// LATENT, NOT LIVE: the relay claims its batch FOR UPDATE SKIP LOCKED, so two
// relays are correct and that is written down below. The point is that nothing
// was checking. The shape the other censuses exist to catch -- a repeating job
// that quietly runs once per replica -- is exactly what this spelling produces,
// and it produces it while passing both guards.
//
// So this census finds the WORK, not the word: every unbounded loop whose body
// waits on a timer. Each one must reach a coordination answer or be named here
// with the reason running it in every replica is correct.
//
// WHAT IT DOES NOT MEASURE. Whether any of these should move into their own
// binary is a question about load, and the plan says the same; nothing here
// claims it.

// periodicRegister is every unbounded timer loop that is NOT leader-gated, with
// why running it in every replica is correct. The value is mandatory.
var periodicRegister = map[string]string{
	"internal/common/events/relay.go::Run": "the outbox relay's poll loop. Two relays are correct rather than " +
		"tolerated: each batch is claimed with SELECT ... FOR UPDATE SKIP LOCKED inside a transaction, so a row " +
		"belongs to exactly one relay and a second replica picks up what the first did not. THE LOCK IS THE " +
		"COORDINATION, which is why there is no leader gate -- and why a future poller copied from this one " +
		"WITHOUT the SKIP LOCKED claim would be the defect this census exists to name.",

	"internal/email/service.go::ProcessQueue": "a queue consumer, not a sweep: it blocks on Redis BRPop, so the " +
		"queue itself distributes the work and more consumers means more throughput, not more duplicates. The " +
		"time.Sleep in it is the backoff after a dequeue ERROR, not the period -- there is no interval here to " +
		"multiply by the replica count.",

	"internal/migrations/migration.go::retryUntilAcquired": "waiting for the migration lock at startup. The lock " +
		"IS the coordination: every replica runs this and exactly one holds it, which is the whole point, and " +
		"the loop ends at a deadline rather than running forever.",

	"internal/access/ziti.go::serveHostedService": "a hosted service's listener lifecycle, and it MUST run in " +
		"every replica -- a terminator is a connection endpoint, so one per pod is the intent and one in total " +
		"would mean every dial landed on a single pod. The timer is the reconnect backoff, not a sweep interval.",

	"cmd/openidx/commands/status.go::NewStatusCommand": "the CLI's status poll, which runs in an operator's " +
		"terminal. There are no replicas of a command somebody typed.",
}

// measuredPeriodicLoops pins the total the derivation finds. A new one is a
// decision somebody has to make; the constant is what makes them make it.
const measuredPeriodicLoops = 5

// timerWaits are the ways a loop can pause. NewTicker is included although the
// sweeps census also sees it: this census must not go quiet because somebody
// rewrote a time.After loop as a ticker in a file that census does not walk.
var timerWaits = map[string]bool{
	"After": true, "Tick": true, "Sleep": true, "NewTimer": true, "NewTicker": true,
}

type periodicLoop struct {
	key   string // "<path>::<func>"
	waits []string
}

// unboundedTimerLoops derives every loop that repeats without a counter and
// waits on a timer inside.
//
// "Unbounded" is `for {}` OR a `for cond {}` with no post statement -- the
// second shape finds nothing on this tree today, and is included anyway so the
// census cannot be accused of being fitted to what happens to be here. A loop
// WITH a post statement (`for i := 0; i < n; i++`) is a bounded retry and is
// deliberately out: retrying eight times with a sleep is not periodic work.
func unboundedTimerLoops(t *testing.T) []periodicLoop {
	t.Helper()
	root := repoRoot(t)
	var out []periodicLoop

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			parsed, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil // a file this package cannot parse is not this census's finding
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)

			for _, decl := range parsed.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					fs, ok := n.(*ast.ForStmt)
					if !ok || fs.Post != nil {
						return true
					}
					waits := map[string]bool{}
					ast.Inspect(fs.Body, func(m ast.Node) bool {
						call, ok := m.(*ast.CallExpr)
						if !ok {
							return true
						}
						sel, ok := call.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						pkg, ok := sel.X.(*ast.Ident)
						if !ok || pkg.Name != "time" || !timerWaits[sel.Sel.Name] {
							return true
						}
						waits[sel.Sel.Name] = true
						return true
					})
					if len(waits) == 0 {
						return true
					}
					names := make([]string, 0, len(waits))
					for k := range waits {
						names = append(names, k)
					}
					sort.Strings(names)
					out = append(out, periodicLoop{key: fmt.Sprintf("%s::%s", rel, fd.Name.Name), waits: names})
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// isLeaderGated reports whether the loop's file hands the work to this package.
func isLeaderGated(t *testing.T, key string) bool {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(strings.SplitN(key, "::", 2)[0]))
	b, err := os.ReadFile(path) //nolint:gosec // a path this census derived from its own walk
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)
	return strings.Contains(src, "RunPeriodic") || strings.Contains(src, "IsLeaderForTick")
}

func TestEveryUnboundedTimerLoopReachesACoordinationAnswer(t *testing.T) {
	loops := unboundedTimerLoops(t)

	if len(loops) != measuredPeriodicLoops {
		t.Errorf("found %d unbounded timer loop(s), measured %d.\n"+
			"A new one is a decision: does it run once per replica, and is that right? Gate it behind "+
			"leader.RunPeriodic, or add it to periodicRegister with the reason every replica should run it, "+
			"and move the constant. If one was REMOVED, lower the constant so the backlog cannot drift back up.",
			len(loops), measuredPeriodicLoops)
	}

	for _, l := range loops {
		if isLeaderGated(t, l.key) {
			continue
		}
		if _, ok := periodicRegister[l.key]; !ok {
			t.Errorf("%s loops forever and waits on time.%s, and nothing says what stops it running once per "+
				"replica.\nThis is the shape the ticker census cannot see: no time.NewTicker in the file, and "+
				"an entry point that is not called Start-anything. Gate it, or write down why every replica "+
				"running it is correct.", l.key, strings.Join(l.waits, "/time."))
		}
	}
}

// The register only shrinks, and every entry has to still be there. An entry
// for a loop that has moved is a reason describing code that no longer exists.
func TestThePeriodicRegisterStillDescribesThisTree(t *testing.T) {
	found := map[string]bool{}
	for _, l := range unboundedTimerLoops(t) {
		found[l.key] = true
	}

	for key, why := range periodicRegister {
		if len(strings.TrimSpace(why)) < 80 {
			t.Errorf("%s: the reason every replica may run this is too thin (%d chars). Say what distributes "+
				"the work -- a lock, a queue, or the fact that one per pod IS the intent.", key, len(strings.TrimSpace(why)))
		}
		if !found[key] {
			t.Errorf("periodicRegister names %s, which this census no longer finds as an unbounded timer loop. "+
				"If it was gated or deleted, drop the line (%s). If it moved, the census stopped seeing it.", key, why)
			continue
		}
		if isLeaderGated(t, key) {
			t.Errorf("periodicRegister names %s, but its file is leader-gated now. Delete the line: the gate is "+
				"a better answer than the register and the register should not claim otherwise.", key)
		}
	}
}

// Vacuity: the derivation must be reading a tree, not an empty walk.
func TestThePeriodicCensusIsReadingSomething(t *testing.T) {
	if got := len(unboundedTimerLoops(t)); got == 0 {
		t.Fatal("the derivation found no unbounded timer loops at all; it is walking the wrong tree or no " +
			"longer recognises the shape, and every assertion above would pass over nothing")
	}
}
