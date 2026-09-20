package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// THE EVENT BUS IS NOT A HARD DEPENDENCY, MEASURED AT THE STARTER.
//
// Decided 2026-09-20: the audit indexer stays on its PostgreSQL-backed path.
// StartESReconciler backfills Elasticsearch from the audit table and needs
// nothing but the database and the search index; the plan's alternative --
// moving it onto the outbox/NATS path and retiring the reconciler -- would
// silently stop the backfill in the default install, where
// elasticsearch.enabled is true and nats.enabled is false. No "events" mode
// switch is added either: a switch to a mode that does not exist is the
// declared-but-nonexistent capability this programme hunts.
//
// So the guard pins the shape rather than the absence of a feature: the
// reconciler's start may sit behind the Elasticsearch gate (`if es != nil`),
// the only gate that names what it actually needs, and behind nothing that
// names the broker. A future edit that wraps it in `if cfg.NATSURL != ""`
// fails here, in the commit that makes it.
var pgBackedStarters = map[string]struct {
	allowedGate string // the one identifier its enclosing `if`s may test
	reason      string
}{
	"StartESReconciler": {"es", "backfills Elasticsearch from the audit table; needs the database and the index, not a broker"},
}

// brokerVocabulary is every identifier that means "an event bus is configured".
var brokerVocabulary = []string{"NATSURL", "NATSUser", "NATSPassword", "nats", "NATS", "Broker", "EventBus", "Outbox", "bus"}

func TestPGBackedStartersAreNotGatedOnTheEventBus(t *testing.T) {
	gates := enclosingGates(t, "main.go")
	for name, want := range pgBackedStarters {
		conds, found := gates[name]
		if !found {
			t.Errorf("%s is not called in main.go; either the starter was renamed (update this register) or the reconciler no longer starts (%s)", name, want.reason)
			continue
		}
		for _, id := range conds {
			for _, broker := range brokerVocabulary {
				if id == broker {
					t.Errorf("%s starts behind a condition naming %s. It %s. Making the event bus a dependency of this path was decided AGAINST on 2026-09-20; see the comment on the call site.", name, id, want.reason)
				}
			}
			if id != want.allowedGate {
				t.Errorf("%s starts behind a condition testing %q; the only gate it may sit behind is %q, the thing it actually needs", name, id, want.allowedGate)
			}
		}
	}
}

// enclosingGates returns, for every Start* call in the file, the sorted set of
// identifiers and selector names tested by the `if` statements enclosing it.
func enclosingGates(t *testing.T, path string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string][]string{}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(sel.Sel.Name, "Start") || len(sel.Sel.Name) == len("Start") {
			return true
		}
		seen := map[string]bool{}
		for _, up := range stack {
			ifs, ok := up.(*ast.IfStmt)
			if !ok {
				continue
			}
			ast.Inspect(ifs.Cond, func(c ast.Node) bool {
				switch v := c.(type) {
				case *ast.Ident:
					if v.Name != "nil" && v.Name != "true" && v.Name != "false" {
						seen[v.Name] = true
					}
				case *ast.SelectorExpr:
					seen[v.Sel.Name] = true
				}
				return true
			})
		}
		var ids []string
		for id := range seen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out[sel.Sel.Name] = append(out[sel.Sel.Name], ids...)
		return true
	})
	if len(out) == 0 {
		t.Fatalf("no Start* call found in %s; the census is reading nothing", path)
	}
	return out
}
