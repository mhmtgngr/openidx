package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// THE SENTENCE THIS GUARDS IS IN LogEvent, AND IT IS ONLY TRUE BY COINCIDENCE.
//
// LogEvent's index write is fire-and-forget: on failure the row stays
// indexed_at IS NULL and, in its own words, "the reconciler catches it --
// guaranteeing ES search completeness without blocking the write path".
//
// That sentence is a claim about the whole deployment, not about this function.
// StartESReconciler runs in exactly one binary. Today the Elasticsearch client
// is also constructed in exactly one binary, and they are the same one, so the
// sentence holds -- I counted rather than trusted it while fixing the ordering
// defect above. But nothing made it hold. A second service given an ES client
// (the console's audit search, a reporting worker, anything) would index
// fire-and-forget with NO reconciler behind it, and every write Elasticsearch
// dropped there would be lost silently: indexed_at stays NULL forever, the row
// is in PostgreSQL, and the console's search simply never shows it.
//
// So the coincidence is now a constraint. Same shape as the sweeps census: the
// test finds the binaries itself rather than trusting a list.
func TestEveryBinaryWithAnElasticsearchClientRunsTheReconciler(t *testing.T) {
	const cmdDir = "../../cmd"

	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read %s: %v", cmdDir, err)
	}
	// Vacuity: an empty or moved cmd/ would satisfy every assertion below.
	if len(entries) < 5 {
		t.Fatalf("only %d entries under %s; this guard is looking at the wrong tree", len(entries), cmdDir)
	}

	var withES, withReconciler []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		calls := map[string]bool{}
		dir := filepath.Join(cmdDir, e.Name())
		files, rerr := os.ReadDir(dir)
		if rerr != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".go" {
				continue
			}
			for name := range callsInFile(t, filepath.Join(dir, f.Name())) {
				calls[name] = true
			}
		}
		if calls["NewElasticsearchFromConfig"] || calls["NewElasticsearch"] {
			withES = append(withES, e.Name())
		}
		if calls["StartESReconciler"] {
			withReconciler = append(withReconciler, e.Name())
		}
	}

	// Vacuity again, and the one that matters: if nothing builds an ES client,
	// this test passes while proving nothing. It would also mean the audit
	// trail has no search index at all.
	if len(withES) == 0 {
		t.Fatal("no binary constructs an Elasticsearch client; either the audit search index is gone " +
			"or this guard no longer recognises how one is built")
	}

	has := make(map[string]bool, len(withReconciler))
	for _, b := range withReconciler {
		has[b] = true
	}
	for _, b := range withES {
		if !has[b] {
			t.Errorf("cmd/%s builds an Elasticsearch client and never calls StartESReconciler.\n"+
				"LogEvent indexes fire-and-forget and says the reconciler backfills whatever the index "+
				"dropped. In this binary nothing would: indexed_at stays NULL forever, the event is in "+
				"PostgreSQL, and the console's audit search never shows it. Start the reconciler here, or "+
				"do not give this service an ES client.", b)
		}
	}

	// And the reverse: a reconciler with no client is a no-op that reads as
	// coverage. StartESReconciler returns immediately when s.es is nil, so this
	// would be silent.
	for _, b := range withReconciler {
		found := false
		for _, e := range withES {
			if e == b {
				found = true
			}
		}
		if !found {
			t.Errorf("cmd/%s calls StartESReconciler but never builds an Elasticsearch client; "+
				"the reconciler returns immediately when es is nil, so this reads as coverage and is a no-op", b)
		}
	}
}

// callsInFile returns the set of function names called in one file, by AST, so
// a name in a comment or a string is not mistaken for a call.
func callsInFile(t *testing.T, path string) map[string]bool {
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
