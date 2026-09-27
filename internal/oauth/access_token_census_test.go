package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY BEARER THIS PACKAGE MINTS IS TYPED AS AN ACCESS TOKEN, AND NOTHING ELSE
// IS.
//
// A validator tells an access token from the other tokens this issuer signs by
// its "at+jwt" header (middleware.IsAccessToken), and newAccessToken is where
// that header is set. Both directions of a mistake are silent at runtime: a
// bearer minted past newAccessToken is refused by every API it is presented to,
// and an ID token minted through it is accepted as a bearer again. So the calls
// are derived from the source and checked against the register the cell-stamp
// census already keeps (cell_claim_census_test.go), whose `stamped` set is by
// its own definition the claim sets presented to an API as a bearer.

// accessTokenMints returns, for every call to newAccessToken and every direct
// call to jwt.NewWithClaims in the package's non-test sources, the claim set
// it signs, keyed file#function#variable as mints() keys them.
func accessTokenMints(t *testing.T) (viaHelper, direct []string) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, pkg := range pkgs {
		for path, f := range pkg.Files {
			file := filepath.Base(path)
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil || fd.Name.Name == "newAccessToken" {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fn := call.Fun.(type) {
					case *ast.Ident:
						if fn.Name == "newAccessToken" && len(call.Args) > 0 {
							viaHelper = append(viaHelper, file+"#"+fd.Name.Name+"#"+argName(call.Args[0]))
						}
					case *ast.SelectorExpr:
						if pkgIdent, ok := fn.X.(*ast.Ident); ok && pkgIdent.Name == "jwt" &&
							fn.Sel.Name == "NewWithClaims" && len(call.Args) > 1 {
							direct = append(direct, file+"#"+fd.Name.Name+"#"+argName(call.Args[1]))
						}
					}
					return true
				})
			}
		}
	}
	sort.Strings(viaHelper)
	sort.Strings(direct)
	return viaHelper, direct
}

// argName is the variable a claim set is passed as, or a description of the
// expression when it is not a plain variable -- which no register entry can
// match, and which therefore fails loudly.
func argName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "<not a variable>"
}

func TestEveryBearerThisPackageMintsIsTypedAsAnAccessToken(t *testing.T) {
	viaHelper, direct := accessTokenMints(t)
	if len(viaHelper) == 0 || len(direct) == 0 {
		t.Fatalf("found %d newAccessToken and %d jwt.NewWithClaims calls; the census is reading nothing",
			len(viaHelper), len(direct))
	}

	typed := map[string]bool{}
	for _, k := range viaHelper {
		typed[k] = true
		if !stamped[k] {
			t.Errorf("%s is signed through newAccessToken, which types it \"at+jwt\", but the register does "+
				"not list it as a bearer (cell_claim_census_test.go `stamped`).\n"+
				"Every API validator accepts an at+jwt token as an access token; an ID token or any other "+
				"token typed that way becomes a credential for the API.", k)
		}
	}
	for _, k := range direct {
		if stamped[k] {
			t.Errorf("%s is a bearer (it is in `stamped`) but is signed with jwt.NewWithClaims directly, so "+
				"it carries no \"at+jwt\" header and every API validator refuses it. Sign it through "+
				"newAccessToken.", k)
		}
	}
	for k := range stamped {
		if !typed[k] {
			t.Errorf("`stamped` names %s as a bearer, but nothing signs it through newAccessToken", k)
		}
	}
}
