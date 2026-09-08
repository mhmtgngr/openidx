package webhooks

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

// The catalogue held against the tree, in both directions.
//
// A subscription form offered ten event types and six of them had no publisher
// anywhere: user.updated and group.updated were emitted only from a file no
// router mounted, and user.locked, login.failed, role.updated, policy.violated
// and review.completed were emitted by nothing at all. An operator subscribed
// an integration, watched an empty delivery log, and had no way to tell a quiet
// week from a control that does not exist.
//
// So: an entry nothing publishes fails, and a publish naming something outside
// the catalogue fails. The list an operator subscribes from cannot drift ahead
// of the code that sends, and the code cannot send something the list does not
// name.

// publishers scans the tree for webhook Publish calls and returns the event
// names it can resolve, plus the sites it cannot.
//
// An unresolvable site is not waved through: in the packages that hold a
// webhook service it fails the test, because an event type hidden behind an
// expression the census cannot read is an event type outside the catalogue's
// reach.
var strictPackages = []string{
	"internal/identity", "internal/oauth", "internal/admin",
	"internal/access", "internal/governance", "internal/provisioning",
}

type scannedFile struct {
	path     string
	pkg      string
	file     *ast.File
	assigned map[string][]string
}

func scanPublishers(t *testing.T) (names map[string][]string, unresolved []string) {
	t.Helper()
	names = map[string][]string{}
	consts := catalogueConstants(t)

	fset := token.NewFileSet()
	var files []scannedFile
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", "testdata":
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			files = append(files, scannedFile{
				path: filepath.ToSlash(path), pkg: f.Name.Name, file: f,
				assigned: localAssignments(f, consts),
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// A publish whose event type is one of the enclosing function's own
	// parameters is not a hole: it is a forwarder, and its callers name the
	// event. internal/identity emits through three of them
	// (emitUserLifecycleEvent and friends), which is the right shape -- one
	// place decides the payload and the detached context -- so the census
	// follows it rather than forcing every call site to inline the Publish.
	forwarders := map[string]int{} // pkg.Func -> index of the event parameter
	for _, sf := range files {
		for _, d := range sf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			params := flattenParams(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				arg, ok := publishEventArg(n)
				if !ok {
					return true
				}
				id, ok := arg.(*ast.Ident)
				if !ok {
					return true
				}
				for i, name := range params {
					if name == id.Name {
						forwarders[sf.pkg+"."+fd.Name.Name] = i
						return false
					}
				}
				return true
			})
		}
	}

	record := func(vals []string, path string) {
		for _, v := range vals {
			names[v] = appendOnce(names[v], path)
		}
	}

	for _, sf := range files {
		ast.Inspect(sf.file, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// A call to a forwarder: the event is the argument in its slot.
			if idx, ok := forwarders[sf.pkg+"."+calleeName(ce)]; ok && idx < len(ce.Args) {
				if vals, ok := resolveEventMulti(ce.Args[idx], consts, sf.assigned); ok {
					record(vals, sf.path)
					return true
				}
			}
			arg, ok := publishEventArg(ce)
			if !ok {
				return true
			}
			// The webhook Publish is Publish(ctx, eventType string, payload).
			// Redis' Publish(ctx, channel, message) and the internal event bus'
			// Publish(ctx, event) land here too and resolve to nothing, which is
			// why unresolved sites are only fatal in the packages that hold a
			// webhook service.
			if vals, ok := resolveEventMulti(arg, consts, sf.assigned); ok {
				record(vals, sf.path)
				return true
			}
			if id, ok := arg.(*ast.Ident); ok && isForwarderParam(sf, ce, id.Name, forwarders) {
				return true // accounted for at this forwarder's call sites
			}
			unresolved = append(unresolved, sf.path+":"+strconv.Itoa(fset.Position(ce.Pos()).Line))
			return true
		})
	}
	return names, unresolved
}

// publishEventArg returns the event-type argument of a webhook Publish call.
func publishEventArg(n ast.Node) (ast.Expr, bool) {
	ce, ok := n.(*ast.CallExpr)
	if !ok || len(ce.Args) < 2 {
		return nil, false
	}
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Publish" {
		return nil, false
	}
	return ce.Args[1], true
}

func calleeName(ce *ast.CallExpr) string {
	switch x := ce.Fun.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// isForwarderParam reports whether this Publish sits inside a function the scan
// already classified as a forwarder.
func isForwarderParam(sf scannedFile, ce *ast.CallExpr, param string, forwarders map[string]int) bool {
	for _, d := range sf.file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || ce.Pos() < fd.Pos() || ce.Pos() > fd.End() {
			continue
		}
		idx, ok := forwarders[sf.pkg+"."+fd.Name.Name]
		if !ok {
			return false
		}
		params := flattenParams(fd)
		return idx < len(params) && params[idx] == param
	}
	return false
}

// flattenParams returns a method's parameter names in call order. The receiver
// is not a parameter, so a method's first argument is index 0.
func flattenParams(fd *ast.FuncDecl) []string {
	var out []string
	if fd.Type.Params == nil {
		return out
	}
	for _, field := range fd.Type.Params.List {
		if len(field.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

// localAssignments records `eventType := EventLoginSuccess` and its later
// reassignments, so a variable that carries one of two constants resolves to
// both rather than to nothing.
func localAssignments(f *ast.File, consts map[string]string) map[string][]string {
	assigned := map[string][]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, l := range as.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok {
				continue
			}
			if v, ok := resolveEvent(as.Rhs[i], consts, nil); ok {
				assigned[id.Name] = appendOnce(assigned[id.Name], v)
			}
		}
		return true
	})
	return assigned
}

// catalogueConstants reads this package's own event constants out of the
// source, so the resolver understands `webhooks.EventUserLocked` without a type
// checker and without a second hand-written list to keep in step.
func catalogueConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "catalogue.go", nil, 0)
	if err != nil {
		t.Fatalf("parse catalogue.go: %v", err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
					out[name.Name] = v
				}
			}
		}
	}
	if len(out) < len(EventCatalogue) {
		t.Fatalf("read %d constants from catalogue.go for %d catalogue entries", len(out), len(EventCatalogue))
	}
	return out
}

func resolveEvent(e ast.Expr, consts map[string]string, assigned map[string][]string) (string, bool) {
	vals, ok := resolveEventMulti(e, consts, assigned)
	if !ok || len(vals) != 1 {
		return "", false
	}
	return vals[0], true
}

func resolveEventMulti(e ast.Expr, consts map[string]string, assigned map[string][]string) ([]string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return nil, false
		}
		v, err := strconv.Unquote(x.Value)
		if err != nil {
			return nil, false
		}
		return []string{v}, true
	case *ast.SelectorExpr: // webhooks.EventUserLocked
		if v, ok := consts[x.Sel.Name]; ok {
			return []string{v}, true
		}
	case *ast.Ident: // EventUserLocked, or a local variable
		if v, ok := consts[x.Name]; ok {
			return []string{v}, true
		}
		if vs, ok := assigned[x.Name]; ok && len(vs) > 0 {
			return vs, true
		}
	}
	return nil, false
}

func appendOnce(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// Every entry an operator can subscribe to is sent by something.
func TestEveryCatalogueEntryHasAPublisher(t *testing.T) {
	names, _ := scanPublishers(t)
	for _, e := range EventCatalogue {
		if len(names[e.Type]) == 0 {
			t.Errorf("%s is offered for subscription and nothing publishes it: "+
				"an operator wiring an integration to it would watch an empty delivery log for ever", e.Type)
		}
	}
}

// And nothing is sent that an operator cannot subscribe to.
func TestEveryPublishedEventIsInTheCatalogue(t *testing.T) {
	names, _ := scanPublishers(t)
	var stray []string
	for name := range names {
		if !KnownEventType(name) {
			stray = append(stray, name+" ("+strings.Join(names[name], ", ")+")")
		}
	}
	sort.Strings(stray)
	for _, s := range stray {
		t.Errorf("%s is published and is not in EventCatalogue: nobody can subscribe to it", s)
	}
}

// A Publish whose event type the census cannot read is a hole in it, and in the
// services that own a webhook publisher that is not allowed.
func TestNoPublishHidesItsEventType(t *testing.T) {
	_, unresolved := scanPublishers(t)
	for _, site := range unresolved {
		for _, pkg := range strictPackages {
			if strings.Contains(site, pkg+"/") {
				t.Errorf("%s: the event type of this Publish cannot be resolved to a catalogue "+
					"constant or a literal, so neither direction of this check covers it", site)
			}
		}
	}
}

// The catalogue is what an operator reads, so every entry says what happened in
// a sentence, not a slug repeated back.
func TestEveryCatalogueEntryDescribesItself(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range EventCatalogue {
		if seen[e.Type] {
			t.Errorf("%s appears twice in the catalogue", e.Type)
		}
		seen[e.Type] = true
		if e.Category == "" {
			t.Errorf("%s has no category", e.Type)
		}
		if len(e.Description) < 20 || !strings.HasSuffix(e.Description, ".") {
			t.Errorf("%s: description %q does not say what happened", e.Type, e.Description)
		}
	}
	if !KnownEventType(EventUserLocked) || KnownEventType("user.exploded") {
		t.Error("KnownEventType does not match the catalogue")
	}
}

// The resolver's own cases, both directions: a literal, a qualified constant, a
// variable assigned two constants, and an expression it must refuse rather than
// guess at.
func TestResolveEvent(t *testing.T) {
	consts := map[string]string{"EventUserLocked": "user.locked", "EventLoginSuccess": "login.success"}
	assigned := map[string][]string{"eventType": {"login.success", "login.high_risk"}}

	parseExpr := func(src string) ast.Expr {
		e, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		return e
	}
	for _, tc := range []struct {
		src  string
		want []string
		ok   bool
	}{
		{`"user.locked"`, []string{"user.locked"}, true},
		{`webhooks.EventUserLocked`, []string{"user.locked"}, true},
		{`EventLoginSuccess`, []string{"login.success"}, true},
		{`eventType`, []string{"login.success", "login.high_risk"}, true},
		{`somethingElse`, nil, false},
		{`fmt.Sprintf("user.%s", verb)`, nil, false},
		{`42`, nil, false},
	} {
		got, ok := resolveEventMulti(parseExpr(tc.src), consts, assigned)
		if ok != tc.ok {
			t.Errorf("resolveEventMulti(%s) ok = %v, want %v", tc.src, ok, tc.ok)
			continue
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("resolveEventMulti(%s) = %v, want %v", tc.src, got, tc.want)
		}
	}
}
