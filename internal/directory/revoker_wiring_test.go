package directory_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// A BINARY THAT RUNS DIRECTORY SYNCS HAS TO GIVE THEM A WAY TO REVOKE.
//
// The sync engine disables or deletes accounts an LDAP directory, an Azure AD
// tenant or an HR feed says have gone. Disabling the row stops the next login;
// /oauth/userinfo and /oauth/introspect read the per-user revocation marker and
// the per-token blacklist and nothing else, so without the callback the
// leaver's access token keeps answering until it expires.
//
// The callback is nil-safe on purpose -- a sync that refuses to run is worse
// than one that leaves a token live -- which is exactly why nothing would
// notice a binary that stopped wiring it.
//
// internal/revocation's sever census cannot see this one: it resolves calls by
// name, and `e.revoke(...)` is a call through a struct field with no declared
// name. Measured, on the equivalent wiring in internal/admin: removing the
// injection everywhere leaves that census green. So the question is answered
// here, where it can be: any binary that STARTS the scheduler must also call
// SetRevoker.
func TestEveryBinaryThatRunsDirectorySyncsWiresTheRevoker(t *testing.T) {
	const cmdDir = "../../cmd"

	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read %s: %v", cmdDir, err)
	}
	if len(entries) < 5 {
		t.Fatalf("only %d entries under %s; this guard is looking at the wrong tree", len(entries), cmdDir)
	}

	var runsSyncs, wiresRevoker []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cmdDir, e.Name())
		files, rerr := os.ReadDir(dir)
		if rerr != nil {
			continue
		}
		// A binary "runs syncs" when it both builds the service and starts it.
		// oauth-service builds one for lookups and never starts the scheduler,
		// so its sync paths do not execute and it needs no revoker.
		builds, starts, wires := false, false, false
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".go" {
				continue
			}
			path := filepath.Join(dir, f.Name())
			fset := token.NewFileSet()
			parsed, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			ast.Inspect(parsed, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, _ := sel.X.(*ast.Ident)
				switch {
				case sel.Sel.Name == "NewService" && recv != nil && recv.Name == "directory":
					builds = true
				case sel.Sel.Name == "Start" && recv != nil && recv.Name == "dirService":
					starts = true
				case sel.Sel.Name == "SetRevoker":
					wires = true
				}
				return true
			})
		}
		if builds && starts {
			runsSyncs = append(runsSyncs, e.Name())
			if wires {
				wiresRevoker = append(wiresRevoker, e.Name())
			}
		}
	}

	// Vacuity: if nothing runs syncs, every assertion below is free -- and it
	// would also mean directory synchronisation is not wired anywhere.
	if len(runsSyncs) == 0 {
		t.Fatal("no binary both builds and starts the directory service; either directory sync is gone " +
			"or this guard no longer recognises how it is started")
	}

	wired := make(map[string]bool, len(wiresRevoker))
	for _, b := range wiresRevoker {
		wired[b] = true
	}
	for _, b := range runsSyncs {
		if !wired[b] {
			t.Errorf("cmd/%s starts directory syncs and never calls SetRevoker.\n"+
				"Those syncs disable or delete accounts an upstream directory says have gone. Without the "+
				"callback the row is disabled and the leaver's access token keeps answering until it "+
				"expires. The field is nil-safe so the sync still runs, which is why nothing else catches "+
				"this.", b)
		}
	}
}
