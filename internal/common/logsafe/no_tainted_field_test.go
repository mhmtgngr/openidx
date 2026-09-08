package logsafe_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A request value must not reach a log field unwashed.
//
// encoder_test.go establishes that a zap FIELD is escaped by both encoders, so
// this is not about forging a log line -- no_interpolated_message_test.go
// guards that. Three reasons to clean a field remain, and they are the package
// comment's:
//
//   - Length. Nothing here bounds a path segment. A megabyte of "id" in every
//     warning fills a disk and buries the entry that mattered.
//   - Sinks that are not zap. These logs are shipped to Elasticsearch and on to
//     a SIEM; the escaping belongs to the encoder, not to the value, and does
//     not survive the next hop.
//   - CodeQL's "Log entries created from user input" rule flags exactly this
//     shape, and it filed alerts against internal/admin/attestation.go for it
//     while three sites in the same file logged a campaign id straight from
//     c.Param. Two other fields in that file already went through logsafe. The
//     earlier sweep fixed what CodeQL had reported rather than the class, which
//     is the mistake this guard exists to stop repeating.
//
// SCOPE. Deliberately narrow, because a guard that reports noise is a guard
// somebody turns off:
//
//   - Only zap.String. A field built any other way is a different question.
//   - Only a value the HANDLER read out of the request in the same function:
//     c.Param, c.Query, c.PostForm, c.GetHeader and their variants. Not
//     c.GetString("user_id") -- that is a value the auth middleware put on the
//     context after validating a token, not text the caller chose.
//   - Function-scoped, not file-scoped. Two functions in one file routinely
//     name different things `id` or `token`, and a file-scoped reading calls
//     the second one tainted because the first one was.
//
// The fix is always logsafe.String(key, value), or zap.String(key,
// logsafe.Clean(value)) where a caller prefers to be explicit. Both are
// accepted here; what is not accepted is the raw value.

// requestReaders are the gin accessors that return text the caller wrote.
var requestReaders = map[string]bool{
	"Param":           true,
	"Query":           true,
	"DefaultQuery":    true,
	"PostForm":        true,
	"DefaultPostForm": true,
	"GetHeader":       true,
	"FormValue":       true,
}

// taintedLocals returns the local identifiers in fn that were assigned the
// result of a request reader.
func taintedLocals(fn ast.Node) map[string]string {
	tainted := map[string]string{}

	record := func(lhs, rhs []ast.Expr) {
		for i, r := range rhs {
			call, ok := r.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !requestReaders[sel.Sel.Name] {
				continue
			}
			if i >= len(lhs) {
				continue
			}
			if id, ok := lhs[i].(*ast.Ident); ok && id.Name != "_" {
				tainted[id.Name] = sel.Sel.Name
			}
		}
	}

	ast.Inspect(fn, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			record(v.Lhs, v.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(v.Names))
			for i, name := range v.Names {
				lhs[i] = name
			}
			record(lhs, v.Values)
		}
		return true
	})
	return tainted
}

// washed reports whether e already goes through this package.
func washed(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "logsafe"
}

// bareIdent returns the identifier e names, seeing through parentheses and a
// pointer dereference (`*userID` is as tainted as `userID`).
func bareIdent(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.ParenExpr:
		return bareIdent(v.X)
	case *ast.StarExpr:
		return bareIdent(v.X)
	}
	return ""
}

// findTaintedFields returns "file:line: detail" for every zap.String in f whose
// value is a request-derived local that nothing cleaned.
func findTaintedFields(fset *token.FileSet, f *ast.File, rel string) []string {
	var found []string

	inspectFunc := func(fn ast.Node) {
		tainted := taintedLocals(fn)
		if len(tainted) == 0 {
			return
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "String" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "zap" {
				return true
			}
			if washed(call.Args[1]) {
				return true
			}
			name := bareIdent(call.Args[1])
			reader, isTainted := tainted[name]
			if !isTainted {
				return true
			}
			found = append(found, rel+":"+strconv.Itoa(fset.Position(call.Args[1].Pos()).Line)+
				": zap.String logs "+name+", read from the request with c."+reader+
				"; use logsafe.String")
			return true
		})
	}

	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			inspectFunc(fn)
		}
	}
	return found
}

func TestNoRequestValueReachesALogFieldUnwashed(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
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
		found = append(found, findTaintedFields(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A guard that greens because it scanned nothing is the failure mode this
	// repository has already been bitten by once.
	if scanned < 100 {
		t.Fatalf("scanned only %d non-test Go files — the walk is looking in the wrong place", scanned)
	}

	if len(found) != 0 {
		sort.Strings(found)
		t.Errorf("%d log field(s) carry a request value nothing cleaned. Each is unbounded text the caller "+
			"chose, shipped to Elasticsearch and onward, and it is the shape CodeQL reports as "+
			"\"Log entries created from user input\". Replace zap.String with logsafe.String:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
}

// The guard rests on being able to see the shape it forbids, and on not seeing
// shapes it must leave alone. Both halves are checked against source built here
// rather than against the tree, so a green tree cannot make this vacuous.
func TestTheTaintedFieldGuardSeesWhatItMust(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
		why  string
	}{
		{
			name: "a raw request value in a field",
			src: `package p
func h(c *gin.Context) {
	id := c.Param("id")
	log.Error("failed", zap.String("id", id))
}`,
			want: 1,
			why:  "this is the whole point",
		},
		{
			name: "logsafe.String",
			src: `package p
func h(c *gin.Context) {
	id := c.Param("id")
	log.Error("failed", logsafe.String("id", id))
}`,
			want: 0,
			why:  "the fix must not be reported as the defect",
		},
		{
			name: "zap.String over logsafe.Clean",
			src: `package p
func h(c *gin.Context) {
	id := c.Param("id")
	log.Error("failed", zap.String("id", logsafe.Clean(id)))
}`,
			want: 0,
			why:  "the explicit spelling is equally clean",
		},
		{
			name: "a dereferenced pointer is still the value",
			src: `package p
func h(c *gin.Context) {
	id := c.Param("id")
	p := &id
	log.Error("failed", zap.String("id", *p))
}`,
			want: 0,
			why:  "the guard does not follow aliases; it must not claim to",
		},
		{
			name: "a constant is not a request value",
			src: `package p
func h(c *gin.Context) {
	id := c.Param("id")
	_ = id
	log.Error("failed", zap.String("stage", "revoke"))
}`,
			want: 0,
			why:  "only the tainted identifier counts",
		},
		{
			name: "a context value is not request text",
			src: `package p
func h(c *gin.Context) {
	actor := c.GetString("user_id")
	log.Error("failed", zap.String("actor", actor))
}`,
			want: 0,
			why:  "the auth middleware put that there after validating a token",
		},
		{
			name: "two functions, one name",
			src: `package p
func a(c *gin.Context) {
	token := c.Query("token")
	_ = token
}
func b() {
	token := mint()
	log.Error("failed", zap.String("family", token))
}`,
			want: 0,
			why:  "a file-scoped reading would call b's token tainted because a's is; that is the false positive that makes a guard useless",
		},
		{
			name: "the same name, tainted in its own function",
			src: `package p
func a(c *gin.Context) {
	token := c.Query("token")
	log.Error("failed", zap.String("token", token))
}
func b() {
	token := mint()
	_ = token
}`,
			want: 1,
			why:  "function scoping must not lose the real one",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := findTaintedFields(fset, f, "x.go")
			if len(got) != c.want {
				t.Errorf("found %d, want %d — %s\n  %s", len(got), c.want, c.why, strings.Join(got, "\n  "))
			}
		})
	}
}
