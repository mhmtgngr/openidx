package access

import (
	"go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"
)

// EVERY MINT SITE ASKS THE QUOTA, MEASURED BY SHAPE.
//
// A function in this package whose body carries a SQL literal that INSERTs
// into agent_enrollment_tokens is a mint site, and it must call
// refuseIfEnrollmentQuotaExceeded before it. Three exist today; the quota was
// added to all three in one commit, and the way a fourth arrives without it is
// exactly the way scope, response_type and PKCE each went missing from one
// authorize handler while present in another: nobody was counting.
//
// The disposition map records every mint site by name. An unlisted one fails
// the build; a listed one that no longer mints is stale and fails too, so the
// map cannot drift from the code in either direction.
var enrollmentMintSites = map[string]string{
	"HandleGenerateToken":       "checks",
	"HandleGenerateQR":          "checks",
	"HandleCreateEnrollSession": "checks",
}

func TestEveryEnrollmentTokenMintSiteAsksTheQuota(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := gotoken.NewFileSet()
	found := map[string]bool{}
	checks := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := goparser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == gotoken.STRING {
						sql := strings.ToUpper(node.Value)
						if strings.Contains(sql, "INSERT INTO AGENT_ENROLLMENT_TOKENS") {
							found[fn.Name.Name] = true
						}
					}
				case *ast.SelectorExpr:
					if node.Sel.Name == "refuseIfEnrollmentQuotaExceeded" {
						checks[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	if len(found) == 0 {
		t.Fatal("no function INSERTs into agent_enrollment_tokens; this guard has stopped measuring anything")
	}
	for name := range found {
		disposition, listed := enrollmentMintSites[name]
		if !listed {
			t.Errorf("%s mints an enrolment token but is not in enrollmentMintSites; call refuseIfEnrollmentQuotaExceeded before the INSERT and list it", name)
			continue
		}
		if disposition == "checks" && !checks[name] {
			t.Errorf("%s is listed as checking the quota but does not call refuseIfEnrollmentQuotaExceeded", name)
		}
	}
	for name := range enrollmentMintSites {
		if !found[name] {
			t.Errorf("enrollmentMintSites lists %s but it no longer INSERTs into agent_enrollment_tokens; remove the stale entry", name)
		}
	}
}
