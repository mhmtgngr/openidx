package oauth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// A TOKEN IS MINTED WITH THE SCOPE OF THE GRANT IT BELONGS TO, NEVER A LITERAL.
//
// GenerateJWT and GenerateIDToken decide which identity claims a token carries
// from the scope they are handed. That makes the ARGUMENT at each call site a
// security control in its own right: a call that passes "openid profile email"
// instead of the grant's own scope hands the client everything, and every test
// that exercises the minting function itself still passes, because the function
// is behaving correctly on the input it was given.
//
// That is not hypothetical. Mutating the token endpoint's `authCode.Scope` to a
// literal left the whole scope suite green until an end-to-end exchange test
// was added; this census is the cheaper guard that also covers the paths with
// no end-to-end test of their own, such as the device-code flow.
//
// The rule: in non-test files of this package, the scope argument must be an
// expression that READS something — a selector like `authCode.Scope`, an
// identifier, a call — not a string literal. A new mint site that hard-codes
// its scope fails here.
func TestEveryTokenMintTakesItsScopeFromTheGrant(t *testing.T) {
	// argument position of `scope` in each minting function's parameter list.
	scopeArg := map[string]int{
		"GenerateJWT":     3, // (ctx, userID, clientID, scope, expiresIn, sessionID...)
		"GenerateIDToken": 4, // (ctx, userID, clientID, nonce, scope, expiresIn, sessionID...)
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	var offenders []string

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
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pos, watched := scopeArg[sel.Sel.Name]
			if !watched || len(call.Args) <= pos {
				return true
			}
			checked++
			if lit, isLit := call.Args[pos].(*ast.BasicLit); isLit {
				offenders = append(offenders, fmt.Sprintf("%s: %s passes the literal %s as its scope",
					fset.Position(call.Pos()), sel.Sel.Name, lit.Value))
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("this census found no mint sites at all, which means it is measuring nothing: " +
			"the function names or their parameter positions changed and scopeArg is stale")
	}
	if len(offenders) > 0 {
		t.Fatalf("a token must be minted with the scope its grant actually carries:\n  %s",
			strings.Join(offenders, "\n  "))
	}
	t.Logf("census: %d mint site(s), every one passing a scope it read", checked)
}
