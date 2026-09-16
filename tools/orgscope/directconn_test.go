package main

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

// The register in directconn.go only shrinks, and every line in it has to keep
// naming a real connection.
//
// This is the half a lint cannot do for itself: at runtime it only asks "is
// this file on the list", so an entry for a file that no longer opens anything
// sits there forever, reading as a reviewed decision about code that is gone.

func directConnFilesOnDisk(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		root := filepath.Join("..", "..", dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			parsed, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			rel := normalizeScanPath(path)
			if strings.HasPrefix(rel, "internal/common/database/") {
				return nil
			}
			ast.Inspect(parsed, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if directConnCalls[callName(call.Fun)] {
					found[rel] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(found) == 0 {
		t.Fatal("no direct connections found anywhere under internal/ or cmd/; the derivation is reading the " +
			"wrong tree and every assertion below would pass over nothing")
	}
	return found
}

func TestEveryDirectConnectionIsRegisteredWithAReason(t *testing.T) {
	found := directConnFilesOnDisk(t)

	var unregistered []string
	for path := range found {
		if _, ok := directConnAllowed[path]; !ok {
			unregistered = append(unregistered, path)
		}
	}
	sort.Strings(unregistered)
	for _, path := range unregistered {
		t.Errorf("%s opens a database connection outside database.NewPostgres and is not in directConnAllowed.\n"+
			"It never becomes a ScopedPool, so neither Raw() rule is ever asked about it, and under FORCE RLS a "+
			"query with no app.org_id is zero rows rather than an error. Write down why its work has no tenant "+
			"to carry.", path)
	}
}

func TestTheDirectConnRegisterDoesNotRot(t *testing.T) {
	found := directConnFilesOnDisk(t)

	for path, why := range directConnAllowed {
		if len(strings.TrimSpace(why)) < 40 {
			t.Errorf("%s: the reason is too thin (%q). Say what makes this connection tenant-free -- that it runs "+
				"before any tenant exists, that it is another database entirely, or that it takes the bypass "+
				"deliberately.", path, why)
		}
		if !found[path] {
			t.Errorf("directConnAllowed names %s, which no longer opens a direct connection.\n"+
				"Delete the line: an entry for code that is gone reads as a reviewed decision and is not one. "+
				"The reason it carried was: %s", path, why)
		}
	}
}
