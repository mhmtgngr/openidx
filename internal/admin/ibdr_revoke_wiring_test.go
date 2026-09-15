package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// THE HOLE THE SEVER CENSUS CANNOT SEE, GUARDED WHERE IT CAN BE.
//
// ibdrService disables the accounts named in a breach incident and cuts their
// outstanding access tokens through the `revoke` function the admin Service
// injects. internal/revocation's census credits a function when it, or
// something it calls, reaches RevokeUserTokens -- and it resolves calls by
// NAME. A call through a struct field has no declared name, so that census
// cannot follow this one and records it as `revokes-indirectly` rather than
// pretending otherwise.
//
// Measured: removing the injection from every construction leaves that census
// green. So the wiring is checked here, next to the constructions, where the
// question is answerable.
//
// A nil field is deliberately not a panic -- containment still runs without a
// revocation client, which is the right failure direction for breach response
// -- and that is exactly why nothing would have noticed it silently becoming
// nil. A quarantine that disables the accounts and leaves their tokens
// answering is the defect this whole census exists for.
func TestEveryQuarantineServiceIsWiredToRevoke(t *testing.T) {
	const file = "ibdr.go"

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var total, wired int
	ast.Inspect(parsed, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		id, ok := lit.Type.(*ast.Ident)
		if !ok || id.Name != "ibdrService" {
			return true
		}
		total++
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "revoke" {
				wired++
			}
		}
		if wired < total {
			t.Errorf("%s:%d builds an ibdrService without a revoke function.\n"+
				"Full quarantine disables the accounts in a breach incident. Disabling the row stops the "+
				"next login; /oauth/userinfo and /oauth/introspect read the per-user revocation marker and "+
				"the per-token blacklist and nothing else, so without this the compromised account's access "+
				"token keeps answering. The field is nil-safe on purpose -- containment must still run -- "+
				"which is why nothing else would catch this.", file, fset.Position(lit.Pos()).Line)
		}
		return true
	})

	// Vacuity: a renamed type or a moved constructor would pass every
	// assertion above while checking nothing.
	if total == 0 {
		t.Fatalf("no ibdrService construction found in %s; this guard is looking at the wrong thing", file)
	}
}
