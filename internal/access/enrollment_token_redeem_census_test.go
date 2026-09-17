package access

import (
	"go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"
)

// THE ONE REDEEMER, MEASURED BY SHAPE.
//
// Both public routes that trade an enrolment token for credentials must go
// through redeemEnrollmentToken, and nothing else in the package may look a
// token up by its presented hash or spend it. A third copy of the check would
// be a third lock on the same door, and the two we had were already different.
//
// Two shapes are pinned across every non-test file in the package:
//   - a SQL literal that names agent_enrollment_tokens AND filters on
//     `token_hash =` (a lookup by the token the client presented) lives only
//     in enrollment_token_redeem.go -- except the revoke-on-cancel in
//     enroll_session.go, which spends nothing and is listed by name;
//   - a SQL literal that sets used_at lives only in enrollment_token_redeem.go.
//
// And both redemption functions call redeemEnrollmentToken.
func TestEveryEnrollmentTokenRedemptionGoesThroughTheOneRedeemer(t *testing.T) {
	const redeemer = "enrollment_token_redeem.go"
	// A literal allowed to filter the token table by token_hash outside the
	// redeemer: the session cancel that marks the token revoked. It admits
	// nothing.
	allowedLookups := map[string]string{
		"enroll_session.go": "SET revoked = true WHERE token_hash",
	}
	mustCall := map[string]bool{
		"HandleEnroll":            false,
		"validateEnrollmentToken": false,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := gotoken.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := goparser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind != gotoken.STRING || !strings.Contains(x.Value, "agent_enrollment_tokens") {
					return true
				}
				pos := fset.Position(x.Pos())
				if strings.Contains(x.Value, "token_hash =") && name != redeemer {
					if want, ok := allowedLookups[name]; !ok || !strings.Contains(x.Value, want) {
						t.Errorf("%s: a lookup of agent_enrollment_tokens by the presented token_hash outside the redeemer; "+
							"every redemption goes through redeemEnrollmentToken", pos)
					}
				}
				if strings.Contains(x.Value, "used_at =") && name != redeemer {
					t.Errorf("%s: spends an enrollment token (SET used_at) outside the redeemer; the spend is the claim and there is one", pos)
				}
			case *ast.FuncDecl:
				fn := x.Name.Name
				if _, tracked := mustCall[fn]; !tracked || x.Body == nil {
					return true
				}
				ast.Inspect(x.Body, func(m ast.Node) bool {
					if call, ok := m.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "redeemEnrollmentToken" {
							mustCall[fn] = true
						}
					}
					return true
				})
			}
			return true
		})
	}
	for fn, calls := range mustCall {
		if !calls {
			t.Errorf("%s does not call redeemEnrollmentToken: a redemption route with its own copy of the check", fn)
		}
	}
	if _, err := os.Stat(redeemer); err != nil {
		t.Fatalf("%s is gone: %v", redeemer, err)
	}
}
