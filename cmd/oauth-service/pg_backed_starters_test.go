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
// Decided 2026-09-20: the SSF transmitter and the two cross-binary seams stay
// on their PostgreSQL-backed paths. ssf_pending_events (v196) is written by
// the severing paths in other binaries and drained here, where the signing key
// is; backchannel_logout_pending (v198) is the same shape for ended sessions;
// the SET outbox is the push worker's queue. The plan's alternative -- these
// as consumers on the NATS path -- would deliver nothing in the default
// install, where nats.enabled is false, and the outbox is single-consumer by
// construction. No "events" mode switch is added: a switch to a mode that
// does not exist is the declared-but-nonexistent capability this programme
// hunts.
//
// The guard pins the shape: these starters run UNCONDITIONALLY. Each needs
// the database it drains and the key this process holds, and nothing else; a
// future edit that wraps one in `if cfg.NATSURL != ""` or any other condition
// fails here, in the commit that makes it.
var pgBackedStarters = map[string]string{
	"StartSSFPushWorker":            "drains the SET outbox to subscribed receivers; idle until a stream is configured, never gated",
	"StartSSFSignalDrainer":         "turns ssf_pending_events rows from other binaries into signed SETs",
	"StartBackchannelLogoutDrainer": "turns backchannel_logout_pending rows from other binaries into logout tokens",
}

func TestPGBackedStartersRunUnconditionally(t *testing.T) {
	gates := enclosingGates(t, "main.go")
	for name, reason := range pgBackedStarters {
		conds, found := gates[name]
		if !found {
			t.Errorf("%s is not called in main.go; either it was renamed (update this register) or a PostgreSQL-backed seam no longer drains (%s)", name, reason)
			continue
		}
		if len(conds) != 0 {
			t.Errorf("%s starts behind a condition testing %v. It %s, so it runs in every install; gating it on a broker was decided AGAINST on 2026-09-20 (see the call site).", name, conds, reason)
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
		if _, dup := out[sel.Sel.Name]; !dup {
			out[sel.Sel.Name] = []string{}
		}
		out[sel.Sel.Name] = append(out[sel.Sel.Name], ids...)
		return true
	})
	if len(out) == 0 {
		t.Fatalf("no Start* call found in %s; the census is reading nothing", path)
	}
	return out
}
