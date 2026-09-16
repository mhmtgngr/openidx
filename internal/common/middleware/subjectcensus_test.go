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

var subjectRegister = map[string]string{
	// key: "<path>::<func>"  value: why it does not bind the subject
	"internal/identity/service.go::openIDXAuthMiddleware": "identity-service does not mount OPAAuthz and does not use " +
		"RequireRole: it authorises with its own handlers, which read the roles it binds itself a few lines " +
		"below this point. Listed rather than changed because binding the subject here would be a no-op that " +
		"looks like a fix.",
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
