// Command inerttests finds Go tests that execute nothing.
//
// Usage:
//
//	inerttests [-fail] <dir>...
//
// THE SHAPE. A test function whose every statement assigns to the blank
// identifier from an expression that CALLS NOTHING:
//
//	func TestService_AuthenticateUser_UnsupportedType(t *testing.T) {
//		service := &Service{logger: newTestLogger()}
//		ctx := context.Background()
//		// We test the error path by checking the method exists and has proper signature
//		_ = service.AuthenticateUser
//		_ = ctx
//	}
//
// `_ = service.AuthenticateUser` is a method VALUE. It is not a call. The
// function under test never runs, nothing is asserted, and the only property
// established -- that the method exists with that name -- the compiler already
// guarantees. Seven of these sat in internal/directory over the directory
// authentication router, one over graceful shutdown named after a function it
// never called, and one that read fields off a zero value it had built itself.
// All nine passed on every CI run of their lives.
//
// WHY THIS IS A SEPARATE TOOL from scripts/check-inert-tests.sh. That guard
// looks for an unconditional t.Skip -- a test that announces it is not running.
// These do not skip. They run, they pass, and they report a tick. Nothing in
// the skip guard can see them.
//
// WHY go/ast RATHER THAN A REGEX. The distinction that matters is whether the
// right-hand side contains a call:
//
//	_ = zeroRole.Level()        // runs code; a nil-safety check. Fine.
//	_ = prometheus.NewRegistry() // runs code. Fine.
//	_ = service.AuthenticateUser // runs nothing. A finding.
//
// A textual match cannot tell a method value from a method call reliably, and a
// guard that reddens on the first two is a guard somebody switches off in a
// week. The parser can, exactly.
//
// DELIBERATELY NARROW. A test that calls something and asserts nothing is not
// reported here: `assert.NotPanics`-style smoke tests, race tests that exist
// for the -race detector, and compile-time interface assertions
// (`var _ Iface = (*T)(nil)`) are all legitimate and all execute something. The
// rule is only: if a test runs no code at all, it is not a test.
//
// An intentional case can carry an inline directive with a mandatory reason,
// on the func line or the line above:
//
//	//inerttests:ignore <reason>
//
// A reason-less directive suppresses nothing and is reported, so an exception
// cannot slip in unexplained.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type finding struct {
	file string
	line int
	name string
}

func main() {
	failOnFindings := flag.Bool("fail", false, "exit non-zero when a test executes nothing")
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	var findings []finding
	scanned := 0
	for _, dir := range dirs {
		f, n, err := scan(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inerttests: %v\n", err)
			os.Exit(2)
		}
		findings = append(findings, f...)
		scanned += n
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "inerttests: %s:%d: %s executes nothing — every statement assigns to _ from an expression that calls nothing\n",
			f.file, f.line, f.name)
	}

	if scanned == 0 {
		fmt.Fprintf(os.Stderr, "inerttests: no _test.go files found under %v — wired to the wrong directory?\n", dirs)
		os.Exit(2)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr,
			"inerttests: %d test(s) that execute nothing across %d test file(s). Call the thing and assert on it, or delete the test — a green tick over code that never ran is worse than no test.\n",
			len(findings), scanned)
		if *failOnFindings {
			os.Exit(1)
		}
		return
	}
	fmt.Printf("inerttests: ok — %d test file(s), every test runs something\n", scanned)
}

func scan(root string) ([]finding, int, error) {
	var out []finding
	scanned := 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch filepath.Base(p) {
			case "vendor", "node_modules", ".git", "third_party", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			// A file that does not parse is the compiler's problem, not ours.
			return nil
		}
		scanned++
		ignored := ignoreLines(fset, f)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			if !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			if !executesNothing(fn.Body) {
				continue
			}
			line := fset.Position(fn.Pos()).Line
			if ignored[line] || ignored[line-1] {
				continue
			}
			out = append(out, finding{file: p, line: line, name: fn.Name.Name})
		}
		return nil
	})
	return out, scanned, err
}

// executesNothing reports whether every statement in the body is a blank
// assignment whose right-hand side calls nothing. A body with no blank
// assignment at all is not this shape and is never reported.
func executesNothing(body *ast.BlockStmt) bool {
	sawBlank := false
	for _, st := range body.List {
		switch v := st.(type) {
		case *ast.AssignStmt:
			if allBlank(v.Lhs) {
				for _, r := range v.Rhs {
					if containsCall(r) {
						return false
					}
				}
				sawBlank = true
				continue
			}
			// A setup assignment (svc := ..., ctx := ...) is allowed: it is the
			// scaffolding these tests build and then never use. What decides the
			// verdict is whether anything is CALLED as a statement.
			continue
		case *ast.DeclStmt:
			continue
		default:
			// An expression statement, a loop, a branch, a defer, a return —
			// anything else is real work or a real decision.
			return false
		}
	}
	return sawBlank
}

func allBlank(lhs []ast.Expr) bool {
	if len(lhs) == 0 {
		return false
	}
	for _, l := range lhs {
		id, ok := l.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return true
}

func containsCall(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if _, ok := x.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// ignoreLines returns the set of lines carrying a reasoned //inerttests:ignore
// directive. A directive with no reason after it is reported and suppresses
// nothing.
func ignoreLines(fset *token.FileSet, f *ast.File) map[int]bool {
	const marker = "//inerttests:ignore"
	out := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(c.Text)
			if !strings.HasPrefix(text, marker) {
				continue
			}
			reason := strings.TrimSpace(strings.TrimPrefix(text, marker))
			line := fset.Position(c.Pos()).Line
			if reason == "" {
				fmt.Fprintf(os.Stderr,
					"inerttests: %s:%d: //inerttests:ignore with no reason suppresses nothing\n",
					fset.Position(c.Pos()).Filename, line)
				continue
			}
			out[line] = true
		}
	}
	return out
}
