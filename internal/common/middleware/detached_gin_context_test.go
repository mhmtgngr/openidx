package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// gin keeps a pool of `*gin.Context` and hands the same one to the next request:
// `Engine.ServeHTTP` takes it from the pool, resets it, and puts it back when the
// handler returns. A goroutine that outlives the handler and then reads from that
// Context is reading a value somebody else now owns.
//
// This is not theory. Three handlers in `internal/oauth` wrote their audit event
// from a detached goroutine and called `c.ClientIP()` inside it, and the race
// detector caught all three at once:
//
//	WARNING: DATA RACE
//	Write at 0x00c000344020 by goroutine 26963:
//	  gin.(*Engine).ServeHTTP()
//	Previous read at 0x00c000344020 by goroutine 26961:
//	  gin.(*Context).ClientIP()
//	  oauth.(*Service).completeSAMLSSO.func1()
//
// The race is the visible half. The quiet half is worse: when the goroutine wins,
// it reads the NEXT request's address, and the audit trail records a sign-in,
// a step-up or a logout as coming from whoever happened to arrive next. An audit
// trail that names the wrong client is not a smaller version of a correct one.
//
// So the rule is: read what you need from the Context BEFORE you detach.
// `clientIP := c.ClientIP()` on the line above `go func()` costs nothing and is
// what the rest of this tree already does (`internal/oauth/external_signin_mfa.go`).
// Passing it as an argument -- `go func(ip string){...}(c.ClientIP())` -- is
// equally fine, because arguments are evaluated where the `go` statement is, not
// where the goroutine runs. `c.Copy()` is gin's own answer when a goroutine needs
// the whole Context, and it must also be called before detaching.
//
// The guard reads the tree rather than a list of remembered sites, for the reason
// the query-parameter census in this package gives: a list cannot cover what
// nobody remembered.
func TestNoDetachedGoroutineReadsAGinContext(t *testing.T) {
	root := censusRepoRoot(t)
	fset := token.NewFileSet()
	var offenders []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)

		ast.Inspect(f, func(n ast.Node) bool {
			names := ginContextParams(n)
			if len(names) == 0 {
				return true
			}
			// Within this function, every `go func(){...}()` that names one of
			// those parameters in its BODY is reading a Context it no longer
			// owns. Its arguments are not: they run before the goroutine does.
			ast.Inspect(n, func(inner ast.Node) bool {
				gos, ok := inner.(*ast.GoStmt)
				if !ok {
					return true
				}
				lit, ok := gos.Call.Fun.(*ast.FuncLit)
				if !ok {
					return true
				}
				ast.Inspect(lit.Body, func(b ast.Node) bool {
					sel, ok := b.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || !names[id.Name] {
						return true
					}
					offenders = append(offenders, rel+":"+
						itoa(fset.Position(sel.Pos()).Line)+
						": the goroutine started at line "+
						itoa(fset.Position(gos.Pos()).Line)+
						" reads "+id.Name+"."+sel.Sel.Name+
						" after the handler may have returned")
					return true
				})
				return true
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// A guard that scanned nothing passes silently, which is the failure this
	// repo has already been bitten by.
	if scanned < 100 {
		t.Fatalf("scanned only %d non-test Go files — the walk is looking in the wrong place", scanned)
	}
	if len(offenders) > 0 {
		t.Errorf("a detached goroutine reads a pooled *gin.Context; read the value before the `go` statement:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// The guard is only worth what it detects, so it is pointed at the shape it
// exists for and at the two shapes that are correct.
func TestTheDetachedContextGuardSeesWhatItMust(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"reads the context inside the goroutine", `package p
func h(c *gin.Context) {
	go func() { log(c.ClientIP()) }()
}`, true},
		{"reads it through a nested goroutine", `package p
func h(c *gin.Context) {
	go func() { go func() { log(c.Request.Host) }() }()
}`, true},
		{"passes the value as an argument", `package p
func h(c *gin.Context) {
	go func(ip string) { log(ip) }(c.ClientIP())
}`, false},
		{"reads it before detaching", `package p
func h(c *gin.Context) {
	ip := c.ClientIP()
	go func() { log(ip) }()
}`, false},
		{"copies the context before detaching", `package p
func h(c *gin.Context) {
	cp := c.Copy()
	go func() { log(cp.ClientIP()) }()
}`, false},
		{"the parameter is not a gin context", `package p
func h(c *http.Request) {
	go func() { log(c.Host) }()
}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			found := false
			ast.Inspect(f, func(n ast.Node) bool {
				names := ginContextParams(n)
				if len(names) == 0 {
					return true
				}
				ast.Inspect(n, func(inner ast.Node) bool {
					gos, ok := inner.(*ast.GoStmt)
					if !ok {
						return true
					}
					lit, ok := gos.Call.Fun.(*ast.FuncLit)
					if !ok {
						return true
					}
					ast.Inspect(lit.Body, func(b ast.Node) bool {
						sel, ok := b.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] {
							found = true
						}
						return true
					})
					return true
				})
				return true
			})
			if found != tc.want {
				t.Errorf("guard reported %v, want %v", found, tc.want)
			}
		})
	}
}

// ginContextParams returns the parameter names of a function declaration or
// literal that are a *gin.Context, or nil when it is neither or takes none.
func ginContextParams(n ast.Node) map[string]bool {
	var params *ast.FieldList
	switch fn := n.(type) {
	case *ast.FuncDecl:
		params = fn.Type.Params
	case *ast.FuncLit:
		params = fn.Type.Params
	default:
		return nil
	}
	if params == nil {
		return nil
	}
	names := map[string]bool{}
	for _, field := range params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Context" {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "gin" {
			continue
		}
		for _, id := range field.Names {
			if id.Name != "_" {
				names[id.Name] = true
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
