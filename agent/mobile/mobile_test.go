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

// hostInterfaces returns every exported interface this package declares,
// mapped to the types its methods take and return.
//
// gomobile binds such an interface in REVERSE — into a Java interface and an
// ObjC protocol the host implements — which is how Keystore reaches the Android
// Keystore and the iOS Keychain from Go. That makes an interface a legitimate
// third type at this boundary beside string and error, but only if its own
// methods are carryable, so the census collects them rather than letting the
// signature check wave through any named type.
func hostInterfaces(t *testing.T) map[string]map[string][]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				return true
			}
			it, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				return true
			}
			methods := map[string][]string{}
			for _, m := range it.Methods.List {
				fn, ok := m.Type.(*ast.FuncType)
				if !ok || len(m.Names) == 0 {
					continue
				}
				var types []string
				for _, list := range []*ast.FieldList{fn.Params, fn.Results} {
					if list == nil {
						continue
					}
					for _, field := range list.List {
						n := len(field.Names)
						if n == 0 {
							n = 1
						}
						for i := 0; i < n; i++ {
							types = append(types, typeName(field.Type))
						}
					}
				}
				methods[m.Names[0].Name] = types
			}
			out[ts.Name.Name] = methods
			return true
		})
	}
	return out
}

// Before Start, every accessor must fail cleanly rather than panic.
func TestNotStartedReturnsError(t *testing.T) {
	resetEngine(t)

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
	resetEngine(t)

	dir := t.TempDir()
	if err := Start(dir, newAESHost(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(s, "enrolled") {
		t.Fatalf("status JSON missing expected field: %q", s)
	}
	if err := Start(dir, newAESHost(t)); err != nil {
		t.Fatalf("second Start (idempotent) should be nil: %v", err)
	}
}

// The whole point of this package is to be gomobile-bindable, so every exported
// binding function must use only types gomobile can carry: string, error, and
// an interface this package declares for the host to implement.
// A non-conforming signature fails here instead of at `gomobile bind`.
//
// The set checked is derived from the package source by exportedBindings, so a
// binding added tomorrow is checked tomorrow. It used to be a map written out
// by hand, and by the time anyone read it again the package had grown a
// seventeenth export -- RegisterPushDevice -- that the map did not name and
// this test therefore never looked at.
func TestSignaturesAreGomobileSafe(t *testing.T) {
	allowed := map[string]bool{"string": true, "error": true}
	for name := range hostInterfaces(t) {
		allowed[name] = true
	}

	for name, types := range exportedBindings(t) {
		for i, tp := range types {
			if !allowed[tp] {
				t.Errorf("%s: type %d is %s, which gomobile cannot carry across the "+
					"boundary; bindings take and return string, error, or an interface "+
					"this package declares for the host to implement", name, i, tp)
			}
		}
	}
}

// TestHostInterfacesAreGomobileSafe. An interface bound in reverse is only
// carryable if its own methods are, and it is bound into TWO languages whose
// generated shapes differ: `String wrap(String)` in Java, `- (NSString*)wrap:`
// in ObjC. A method returning (string, error) has a different spelling in each
// -- `throws Exception` on one side, a BOOL and an out-parameter on the other --
// and the host halves of this boundary are only ever compiled by CI, so a
// surprise is either a broken build or a call that compiles and does the wrong
// thing. One String in and one String out has exactly one spelling in both, and
// that is what this pins.
func TestHostInterfacesAreGomobileSafe(t *testing.T) {
	ifaces := hostInterfaces(t)
	if len(ifaces) == 0 {
		t.Skip("this package declares no host interface")
	}
	for iface, methods := range ifaces {
		if len(methods) == 0 {
			t.Errorf("%s declares no method; an empty host interface is bound to nothing", iface)
		}
		for method, types := range methods {
			for i, tp := range types {
				if tp != "string" {
					t.Errorf("%s.%s: type %d is %s. A reverse-bound method must take and "+
						"return string only -- (string, error) generates a different shape "+
						"in Java than in ObjC, and both are hand-written host code that no "+
						"Go build ever sees.", iface, method, i, tp)
				}
			}
		}
	}
}
