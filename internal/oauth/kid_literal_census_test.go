package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// A TOKEN NAMES THE KEY THAT SIGNED IT, AND THAT NAME IS NEVER A LITERAL.
//
// generateStepUpToken stamped kid "openidx-key-1" as a string literal while
// signing with whatever key was active. On a fresh install the active key is
// openidx-key-<hex>; after the first rotation it is another; in a named cell
// it is <cell>-key-<hex>. In every one of those the token named a key that
// had not signed it. The shape of that defect is an assignment to a kid
// header whose right-hand side is a string literal; this walks every non-test
// file in the package and refuses the shape. The value must come from the
// signer (signingKey) or a variable that did.
func TestNoTokenInThisPackageWearsALiteralKid(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				idx, ok := lhs.(*ast.IndexExpr)
				if !ok {
					continue
				}
				key, ok := idx.Index.(*ast.BasicLit)
				if !ok || key.Value != `"kid"` {
					continue
				}
				sel, ok := idx.X.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Header" {
					continue
				}
				seen++
				if i < len(assign.Rhs) {
					if lit, isLit := assign.Rhs[i].(*ast.BasicLit); isLit {
						t.Errorf("%s: kid header set to the literal %s; a token names the key that signed it, "+
							"so the kid comes from signingKey()", fset.Position(lit.Pos()), lit.Value)
					}
				}
			}
			return true
		})
	}
	if seen < 5 {
		t.Fatalf("found only %d kid header assignments in the package; the census lost its subject", seen)
	}
}
