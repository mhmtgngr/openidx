package middleware_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY AUTHENTICATION MIDDLEWARE HAS TO BIND THE SUBJECT, and this counts the
// ones that do not.
//
// The authorization layers downstream read the caller's identity out of the gin
// context and nowhere else: OPAAuthz builds opa.Input.User from "roles" and
// "groups", RequireRole reads "roles". Each service that fronts them brought
// its own authentication middleware, and what those bound had drifted:
// governance-service and provisioning-service bound user_id, email and name and
// neither roles nor groups, so with ENABLE_OPA_AUTHZ on, a policy that opens
// `default allow := false` and grants by role was deciding on an empty list.
//
// A single test of one middleware would not have caught that, because each
// middleware was individually fine by its own lights. So this finds the
// authentication middlewares itself rather than trusting a list -- the same
// shape as internal/revocation's sever census -- and anything left over must be
// in the register below WITH A REASON. An entry that stops reproducing fails
// the run, so the list can only shrink.

// The register is empty, and the entry that used to be here is worth recording
// because of HOW it stopped being true.
//
// identity-service's openIDXAuthMiddleware was listed with the reason that it
// mounts neither OPAAuthz nor RequireRole -- it authorises with
// requireAdminUnlessSelfService, which reads the roles that middleware bound by
// hand -- so calling the shared binder would have been a no-op wearing the
// shape of a fix. That was true of ROLES AND GROUPS. It stopped being true of
// the function when BindSubjectClaims took on a third key: the cell that minted
// the token, which cell.Guard reads and nothing in identity was setting. The
// register's reason had not changed; what the function did had.
//
// So an exemption is a claim about a moment, not a property. This one is now
// the load-bearing reason identity-service can refuse a misdirected request at
// all (internal/identity/cell_guard_test.go).
var subjectRegister = map[string]string{
	// key: "<path>::<func>"  value: why it does not bind the subject
}

func TestEveryAuthMiddlewareBindsTheSubject(t *testing.T) {
	found, binds := subjectCensus(t)

	if len(found) < 3 {
		t.Fatalf("only %d authentication middleware(s) found; this census is looking at the wrong tree or no "+
			"longer recognises how a token is turned into a caller", len(found))
	}

	var missing []string
	for _, key := range found {
		if binds[key] {
			continue
		}
		if _, ok := subjectRegister[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		t.Errorf("%s turns a verified token into a caller but never binds the subject.\n"+
			"OPAAuthz builds its authorization input from c.Get(\"roles\") and c.Get(\"groups\"), and "+
			"RequireRole reads c.Get(\"roles\"); a middleware that omits them hands every rule downstream an "+
			"empty identity, which authz.rego -- `default allow := false` -- turns into a denial rather than "+
			"an error anybody would notice. Call middleware.BindSubjectClaims(c, claims), or record the "+
			"reason in subjectRegister.", key)
	}

	for key, reason := range subjectRegister {
		seen := false
		for _, k := range found {
			if k == key {
				seen = true
			}
		}
		if !seen {
			t.Errorf("subjectRegister names %s, which this census no longer finds as an authentication "+
				"middleware. If it was fixed, delete the line (%s). If it moved, the census stopped seeing it.",
				key, reason)
			continue
		}
		if binds[key] {
			t.Errorf("subjectRegister names %s, but it binds the subject now. Delete the line.", key)
		}
	}
}

// subjectCensus finds every function that turns verified token claims into a
// caller -- it reads a claims map AND writes the caller's id into the request
// context -- and reports which of them bind the subject.
func subjectCensus(t *testing.T) (found []string, binds map[string]bool) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "internal")
	binds = map[string]bool{}
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		parsed, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join("..", "..", ".."), path)
		for _, decl := range parsed.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			var setsUserID, readsClaims, bindsSubject bool
			ast.Inspect(fd, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CallExpr:
					// Both spellings: middleware.BindSubjectClaims from another
					// package, and the bare identifier from inside this one.
					// Matching only the qualified form would have reported this
					// package's own middlewares as the offenders -- which is
					// exactly what it did on the first run.
					if ident, ok := e.Fun.(*ast.Ident); ok && ident.Name == "BindSubjectClaims" {
						bindsSubject = true
					}
					sel, ok := e.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sel.Sel.Name == "BindSubjectClaims" {
						bindsSubject = true
					}
					// c.Set("user_id", ...)
					if sel.Sel.Name == "Set" && len(e.Args) > 0 {
						if lit, ok := e.Args[0].(*ast.BasicLit); ok &&
							lit.Kind == token.STRING && strings.Contains(lit.Value, "user_id") {
							setsUserID = true
						}
					}
				case *ast.IndexExpr:
					// claims["sub"], claims["roles"], ...
					if ident, ok := e.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(ident.Name), "claims") {
						readsClaims = true
					}
				}
				return true
			})
			if !setsUserID || !readsClaims {
				continue
			}
			key := fmt.Sprintf("%s::%s", filepath.ToSlash(rel), fd.Name.Name)
			found = append(found, key)
			binds[key] = bindsSubject
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(found)
	return found, binds
}
