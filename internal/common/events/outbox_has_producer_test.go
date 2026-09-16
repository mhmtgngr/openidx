package events

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// THE OTHER END OF THE SAME GUARD.
//
// outbox_is_run_test.go measures that some binary DRAINS the outbox, and its
// own doc says it "fails when the answer to 'does anything actually publish
// these events' becomes no". Measured: the answer is no, and it does not fail.
// NewOutboxBus has no caller outside this package. events.Event is constructed
// nowhere outside this package. The only INSERT INTO outbox in production code
// is inside OutboxBus.Publish itself. cmd/event-relay drains a table that
// nothing writes to.
//
// The guard was watching the consumer and reporting on the producer. That is
// not a criticism of the guard's author -- it is the defect shape this whole
// tree keeps finding, in the guard written to prevent it: a control that
// reports success while the thing it exists to make true is not true.
//
// WHAT THIS IS NOT. It is not a demand that something publish. An outbox with
// no producer is a legitimate state for infrastructure that was built ahead of
// its first use -- AS LONG AS IT IS STATED. What was live here was the silence:
// a plan that described the event path as finished, and a guard that agreed.
//
// THE DECISION THIS ENCODES. The event path is an ACCELERATOR, not a
// dependency. nats.enabled defaults false; elasticsearch.enabled defaults true;
// and the paths that were proposed as the outbox's first producers -- the audit
// indexer, SSF transmission -- each already have a completion guarantee that
// needs no broker: the indexer reconciles against indexed_at IS NULL in
// PostgreSQL, SSF posts to partner endpoints over HTTP with its own retry.
// Moving either onto the bus would replace a guarantee that self-heals from
// durable state with a delivery that, in the default install, never happens.
// So the register below does two things: it records why there is no producer
// today, and it requires every FUTURE producer to name the completion
// guarantee it keeps when the broker is absent. A producer that cannot name one
// does not belong on this bus.

// noProducerYet is the stated reason the outbox has no producer. It must be
// EMPTY the moment one exists, or the statement is stale and the test says so.
const noProducerYet = "Built ahead of its first use. The audit indexer and SSF transmission were considered " +
	"and rejected as producers: each has a broker-free completion guarantee today (PostgreSQL " +
	"reconciliation; HTTP delivery with retry) that the bus would weaken in the default install, " +
	"where nats.enabled is false. The first producer will be something whose delivery is an " +
	"improvement over nothing rather than a replacement for something that works."

// producers is the register every outbox producer must appear in, keyed by
// "<path>::<func>", with the completion guarantee it keeps WITHOUT the broker.
// An entry that stops reproducing fails; a producer with no entry fails.
var producers = map[string]string{}

// TestTheOutboxHasAProducerOrSaysWhyNot is the producer-side reachability
// check the consumer-side guard was standing in for.
func TestTheOutboxHasAProducerOrSaysWhyNot(t *testing.T) {
	found, scanned := outboxProducers(t)

	if scanned < 200 {
		t.Fatalf("scanned only %d Go files; this census is looking at the wrong tree", scanned)
	}

	if len(found) == 0 {
		if noProducerYet == "" {
			t.Fatalf("nothing outside internal/common/events constructs an OutboxBus, and noProducerYet is " +
				"empty. Either something is meant to publish and does not -- in which case cmd/event-relay is " +
				"draining a table nothing writes to, the exact state this package's own doc records as the " +
				"reason its predecessor was deleted -- or the state is intentional and has to be SAID here.")
		}
		return // no producer, and the reason is written down: the honest state
	}

	if noProducerYet != "" {
		t.Errorf("noProducerYet is set, but %d producer(s) exist: %v. Delete the statement; it is stale.",
			len(found), found)
	}
	for _, key := range found {
		if _, ok := producers[key]; !ok {
			t.Errorf("%s publishes to the outbox and is not in the producers register.\n"+
				"Every producer must name the completion guarantee it keeps when the broker is ABSENT -- "+
				"nats.enabled defaults false, so in the default install this publish reaches nobody. If the "+
				"outcome this event carries matters without NATS, say what makes it happen without NATS. If "+
				"nothing does, this event should not be on the bus.", key)
		}
	}
	for key, why := range producers {
		seen := false
		for _, f := range found {
			if f == key {
				seen = true
			}
		}
		if !seen {
			t.Errorf("producers names %s, which no longer constructs an OutboxBus (%s). Delete the line.", key, why)
		}
	}
}

// TestTheConsumerSideGuardDoesNotAlsoClaimTheProducerSide keeps the two guards
// honest about their scope: the drain test's doc used to say it would fail when
// nothing publishes, which it cannot see. The sentence is checked so that the
// scope statement cannot quietly grow back.
func TestTheConsumerSideGuardDoesNotAlsoClaimTheProducerSide(t *testing.T) {
	b, err := os.ReadFile("outbox_is_run_test.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(b), `"does anything actually publish these events"`) {
		t.Errorf("outbox_is_run_test.go still claims to fail when nothing publishes. It measures the DRAIN " +
			"(NewRelay, NewNATSSink in cmd/) and cannot see a producer; that is this file's job. Fix the doc " +
			"so the two guards say what they each measure.")
	}
}

// outboxProducers walks internal/ and cmd/ for production files that construct
// an OutboxBus, by AST call name, and returns them as "<path>::<func>".
func outboxProducers(t *testing.T) (found []string, scanned int) {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/common/events/") {
				return nil // the package itself is not a producer
			}
			scanned++
			for fn, calls := range callsByFunc(t, path) {
				if calls["NewOutboxBus"] {
					found = append(found, rel+"::"+fn)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	sort.Strings(found)
	return found, scanned
}

// callsByFunc is callsIn split per top-level function, so a producer is named
// by the function that constructs the bus rather than by its file.
func callsByFunc(t *testing.T, path string) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]map[string]bool{}
	for _, decl := range parsed.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				calls[fn.Name] = true
			case *ast.SelectorExpr:
				calls[fn.Sel.Name] = true
			}
			return true
		})
		out[fd.Name.Name] = calls
	}
	return out
}
