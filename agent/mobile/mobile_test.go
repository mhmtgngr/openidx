package mobile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exportedBindings parses this package's own source for every exported
// function, and returns each one's parameter and result type names as written.
//
// It is derived rather than listed because the list is the thing that goes
// wrong. TestSignaturesAreGomobileSafe below used to hold a map of sixteen
// functions written out by hand; the package exports seventeen, and the one
// missing was RegisterPushDevice -- the push-registration binding, whose
// signature all three platform bridges depend on. A census that is one entry
// short reads exactly like a census that is complete.
func exportedBindings(t *testing.T) map[string][]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	sigs := map[string][]string{}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			// Methods are not gomobile bindings at the package level, and
			// unexported functions are not bound at all.
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			var types []string
			for _, field := range fn.Type.Params.List {
				// One field can name several parameters sharing a type.
				n := len(field.Names)
				if n == 0 {
					n = 1
				}
				for i := 0; i < n; i++ {
					types = append(types, typeName(field.Type))
				}
			}
			if fn.Type.Results != nil {
				for _, field := range fn.Type.Results.List {
					n := len(field.Names)
					if n == 0 {
						n = 1
					}
					for i := 0; i < n; i++ {
						types = append(types, typeName(field.Type))
					}
				}
			}
			sigs[fn.Name.Name] = types
		}
	}

	if files == 0 {
		t.Fatal("no non-test .go file found in this package; the census read nothing and would pass vacuously")
	}
	if len(sigs) == 0 {
		t.Fatal("no exported function found in this package; a gomobile binding package with no bindings is not a thing to pass silently")
	}
	return sigs
}

// typeName renders a type expression as written. Anything that is not a bare
// identifier is by definition not `string` or `error`, so rendering it
// approximately is enough to fail it with a readable message.
func typeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return "*" + typeName(v.X)
	case *ast.SelectorExpr:
		return typeName(v.X) + "." + v.Sel.Name
	case *ast.ArrayType:
		return "[]" + typeName(v.Elt)
	case *ast.MapType:
		return "map[" + typeName(v.Key) + "]" + typeName(v.Value)
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.Ellipsis:
		return "..." + typeName(v.Elt)
	default:
		return "unsupported"
	}
}

// Before Start, every accessor must fail cleanly rather than panic.
func TestNotStartedReturnsError(t *testing.T) {
	mu.Lock()
	engine = nil
	mu.Unlock()

	if _, err := Status(); err == nil {
		t.Fatal("Status before Start should error")
	}
	if err := Logout(); err == nil {
		t.Fatal("Logout before Start should error")
	}
}

// Start against a fresh (unenrolled) config dir must succeed and be idempotent,
// and Status must then return a non-empty JSON payload.
func TestStartAndStatus(t *testing.T) {
	mu.Lock()
	engine = nil
	mu.Unlock()

	dir := t.TempDir()
	if err := Start(dir); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(s, "enrolled") {
		t.Fatalf("status JSON missing expected field: %q", s)
	}
	if err := Start(dir); err != nil {
		t.Fatalf("second Start (idempotent) should be nil: %v", err)
	}
}

// The whole point of this package is to be gomobile-bindable, so every exported
// binding function must use only gomobile-safe types (string / error) across the
// boundary. A non-conforming signature fails here instead of at `gomobile bind`.
//
// The set checked is derived from the package source by exportedBindings, so a
// binding added tomorrow is checked tomorrow. It used to be a map written out
// by hand, and by the time anyone read it again the package had grown a
// seventeenth export -- RegisterPushDevice -- that the map did not name and
// this test therefore never looked at.
func TestSignaturesAreGomobileSafe(t *testing.T) {
	for name, types := range exportedBindings(t) {
		for i, tp := range types {
			if tp != "string" && tp != "error" {
				t.Errorf("%s: type %d is %s, which gomobile cannot carry across the "+
					"boundary; bindings take and return only string and error", name, i, tp)
			}
		}
	}
}
