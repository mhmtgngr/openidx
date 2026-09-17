package events

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// THE GUARD AGAINST THIS PACKAGE BECOMING WHAT IT REPLACED.
//
// The package doc records why the in-memory bus was deleted: 346 lines, and
// NOTHING IN THE TREE IMPORTED IT. The outbox then spent two tasks in exactly
// that position -- a table no production code wrote to, a relay no process ran
// -- and the plan said so in as many words rather than letting it pass as
// finished. What kept it from being the same defect was intention, which is not
// a property a test can check and not one that survives a year.
//
// So: some binary in cmd/ has to run the relay, and it has to run it with a
// sink that reaches a broker. A relay constructed with a stub would satisfy the
// letter of "the relay is run" while delivering nothing, which is the failure
// this is really about.
//
// This is a REACHABILITY test, not a style rule, and it measures ONE END: that
// a process drains the outbox into a real broker. It cannot see whether
// anything WRITES the outbox -- that is outbox_has_producer_test.go, which was
// written when this doc claimed to cover both and measurement showed it did
// not: nothing outside this package constructs an OutboxBus, and this test was
// green.
func TestSomeBinaryRunsTheOutboxRelay(t *testing.T) {
	const cmdDir = "../../../cmd"

	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read %s: %v", cmdDir, err)
	}
	// Vacuity: an empty or moved cmd/ would make every assertion below pass.
	if len(entries) < 5 {
		t.Fatalf("only %d entries under %s; this guard is looking at the wrong tree", len(entries), cmdDir)
	}

	var runsRelay, buildsSink []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cmdDir, e.Name())
		files, rerr := os.ReadDir(dir)
		if rerr != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".go" {
				continue
			}
			path := filepath.Join(dir, f.Name())
			called := callsIn(t, path)
			if called["NewRelay"] {
				runsRelay = append(runsRelay, e.Name())
			}
			if called["NewNATSSink"] {
				buildsSink = append(buildsSink, e.Name())
			}
		}
	}

	if len(runsRelay) == 0 {
		t.Errorf("no binary under cmd/ calls events.NewRelay.\n" +
			"The outbox table, the publisher and the relay are all measured, and none of it delivers anything " +
			"until a process runs the drain. A table nothing writes to differs from a package nothing imports " +
			"only by intention -- see this package's own doc for what happened to the last one.")
	}
	if len(buildsSink) == 0 {
		t.Errorf("no binary under cmd/ calls events.NewNATSSink.\n" +
			"A relay wired to a stub satisfies \"the relay runs\" and delivers nothing, which is the failure " +
			"this guard is about rather than the constructor call.")
	}
}

// callsIn returns the set of function names called in one file, by AST, so a
// name inside a comment or a string is not mistaken for a call.
func callsIn(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]bool{}
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			out[fn.Name] = true
		case *ast.SelectorExpr:
			out[fn.Sel.Name] = true
		}
		return true
	})
	return out
}
