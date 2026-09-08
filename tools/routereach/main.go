// Command routereach holds the router's route table next to the handlers the
// package defines, and reports the two ways they disagree.
//
// Usage:
//
//	routereach [-fail] [-census] <dir>...
//
// THE SHAPE. `DELETE /users/:id/bypass-codes` is how an administrator revokes
// every MFA break-glass code a user holds -- the thing you do the moment a
// bypass code leaks. Its handler opens:
//
//	requestedUserID := c.Param("user_id")
//
// The route declares :id, not :user_id. gin returns "" for a name the matched
// route does not declare, so the handler asks the database to revoke the codes
// of the empty user, and PostgreSQL answers
//
//	ERROR: invalid input syntax for type uuid: ""
//
// The endpoint has never once revoked a code, on any install, and the error it
// returns is a 400 that reads like the administrator sent something wrong.
//
// This is the family this repository keeps finding, at the routing layer: a
// control that displays without enforcing, a table with no writer, a test that
// runs nowhere -- and now a parameter with no route, and a handler with no
// router. In each case the thing exists, looks complete in review, and does
// nothing.
//
// TWO FINDINGS.
//
//	param      a handler reads c.Param("x") and no route it is mounted on
//	           declares x. gin cannot tell the handler this; it returns "".
//	unmounted  a func(*gin.Context) that no route registration names and no
//	           other line of non-test code references. It is a handler no
//	           request can reach.
//
// WHY THE PARAM CHECK IS EXACT HERE. A gin route's parameters come from its own
// path and from the prefixes of the groups it is registered under. In this tree
// no .Group() literal contains a ':' or '*' -- checked, all 43 of them -- so a
// route's own path is the whole source of its parameter names, and the check
// needs no interprocedural prefix analysis to be sound.
//
// REACHABILITY IS PROPAGATED. A handler that hands its *gin.Context to a helper
// which reads c.Param is checked against the routes of every handler that can
// reach that helper, to a fixpoint over same-package calls. The union is the
// right answer: a helper shared by /users/:id and /groups/:id may legitimately
// read either name.
//
// TESTS DO NOT COUNT AS A MOUNT. _test.go files are not scanned, deliberately.
// A handler whose only caller is a test that mounts it on a router the test
// built is the sharpest form of this finding: the test passes, proves the code
// works, and no request will ever arrive at it. internal/oauth's discovery
// document was found exactly that way -- 415 lines of test for an OIDC
// discovery handler no service mounts, beside a second, different discovery
// document that every relying party actually reads.
//
// Findings are registered in known.go with a verdict apiece. A finding absent
// from the register fails the run; an entry that no longer reproduces fails it
// too, so the register can only shrink.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 on an unregistered finding or a stale register entry")
	census := flag.Bool("census", false, "print every route with its parameters and the handler it resolves to")
	flag.Parse()

	dirs := flag.Args()
	if len(dirs) == 0 {
		dirs = []string{"./internal", "./cmd", "./pkg"}
	}

	srcs, fset, err := parseTree(dirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "routereach: %v\n", err)
		os.Exit(2)
	}

	res := analyze(fset, srcs)

	if *census {
		for _, r := range res.Routes {
			fmt.Printf("%-6s %-58s params=[%s] -> %s\n",
				r.Method, r.Path, strings.Join(r.Params, " "), strings.Join(r.Handlers, ", "))
		}
		return
	}

	// A parameterised route whose handler cannot be resolved is not a passing
	// route, it is an unchecked one -- the hole every register in this
	// repository exists to keep visible.
	for _, r := range res.Blind {
		fmt.Printf("%s %s: declares %v and no handler could be resolved\n", r.Method, r.Path, r.Params)
		fmt.Printf("    registered at %s\n", r.Pos)
	}

	var unregistered []unmountedFinding
	for _, f := range res.Unmounted {
		if _, ok := knownUnmounted[f.Key]; !ok {
			unregistered = append(unregistered, f)
		}
	}
	found := make(map[string]bool, len(res.Unmounted))
	for _, f := range res.Unmounted {
		found[f.Key] = true
	}
	var stale []string
	for key := range knownUnmounted {
		if !found[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	for _, f := range res.Params {
		fmt.Printf("%s:%d: %s reads c.Param(%q)\n", f.File, f.Line, f.Func, f.Name)
		fmt.Printf("    its route(s) declare [%s]: %s\n", strings.Join(f.Declared, " "), strings.Join(f.Routes, ", "))
		fmt.Printf("    gin returns \"\" for a name the matched route does not declare\n")
	}
	for _, f := range unregistered {
		fmt.Printf("%s:%d: %s takes *gin.Context and no route mounts it\n", f.File, f.Line, f.Key)
		fmt.Printf("    no non-test line of this tree references it\n")
	}
	for _, key := range stale {
		fmt.Printf("%s: registered as unmounted, but a route reaches it now\n", key)
		fmt.Printf("    remove its entry from tools/routereach/known.go\n")
	}

	fmt.Fprintf(os.Stderr,
		"routereach: %d route(s), %d handler-shaped func(s), %d param finding(s), %d unmounted (%d registered, %d new, %d stale), %d blind route(s)\n",
		len(res.Routes), res.HandlerShaped, len(res.Params), len(res.Unmounted),
		len(knownUnmounted), len(unregistered), len(stale), len(res.Blind))

	if *failOnFindings && (len(res.Params) > 0 || len(unregistered) > 0 || len(stale) > 0 || len(res.Blind) > 0) {
		os.Exit(1)
	}
}

// --- inputs ------------------------------------------------------------

type source struct {
	Path string
	Pkg  string
	File *ast.File
}

// parseTree reads every non-test Go file under dirs.
//
// A parse failure is fatal rather than skipped, for the reason the sibling
// sweeps learned the hard way: a file that fails to parse is a file whose
// findings vanish, and the run then reports FEWER findings, which reads exactly
// like a fix.
func parseTree(dirs []string) ([]source, *token.FileSet, error) {
	fset := token.NewFileSet()
	var out []source
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
				return fmt.Errorf("%s: %w", path, perr)
			}
			out = append(out, source{Path: path, Pkg: f.Name.Name, File: f})
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return out, fset, nil
}

// --- the analysis ------------------------------------------------------

type route struct {
	Method   string
	Path     string
	Params   []string
	Handlers []string
	Pos      string
}

type paramFinding struct {
	Func     string
	Name     string
	File     string
	Line     int
	Declared []string
	Routes   []string
}

type unmountedFinding struct {
	Key  string // pkg.FuncName
	File string
	Line int
}

type result struct {
	Routes        []route
	Blind         []route // declares parameters, resolves to no handler
	Params        []paramFinding
	Unmounted     []unmountedFinding
	HandlerShaped int
}

var routeVerbs = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "Any": true,
}

// pathParams returns the wildcard names a gin path declares. gin spells them
// :name (one segment) and *name (the rest of the path).
func pathParams(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 1 && (seg[0] == ':' || seg[0] == '*') {
			out = append(out, seg[1:])
		}
	}
	return out
}

// body is a function body that may read c.Param: either a declared function or
// a closure passed straight to a route registration.
type body struct {
	key  string
	node ast.Node
	pkg  string
}

func analyze(fset *token.FileSet, srcs []source) result {
	var res result

	// Every declared function, keyed pkg.Name. A package with two methods of
	// the same name on different types collapses to one key; the effect is that
	// both are treated as mounted when either is, which errs towards silence
	// rather than towards a false finding.
	decls := map[string][]*ast.FuncDecl{}
	for _, s := range srcs {
		for _, d := range s.File.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				decls[s.Pkg+"."+fd.Name.Name] = append(decls[s.Pkg+"."+fd.Name.Name], fd)
			}
		}
	}

	bodies := map[string]*body{}
	for key, ds := range decls {
		pkg := key[:strings.IndexByte(key, '.')]
		for i, d := range ds {
			bodies[bodyKey(key, i)] = &body{key: bodyKey(key, i), node: d, pkg: pkg}
		}
	}

	// available[bodyKey] is the union of parameter names the routes that reach
	// this body declare. A body absent from the map is reached by no route.
	available := map[string]map[string]bool{}
	routesOf := map[string][]string{}

	for _, s := range srcs {
		ast.Inspect(s.File, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || !routeVerbs[sel.Sel.Name] || len(ce.Args) < 2 {
				return true
			}
			lit, ok := ce.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			path, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.HasPrefix(path, "/") {
				return true
			}

			r := route{
				Method: sel.Sel.Name,
				Path:   path,
				Params: pathParams(path),
				Pos:    fset.Position(lit.Pos()).String(),
			}
			label := r.Method + " " + r.Path

			for _, arg := range ce.Args[1:] {
				// A registration may wrap its handler in middleware, so every
				// function-valued name inside the argument is a candidate.
				ast.Inspect(arg, func(m ast.Node) bool {
					var keys []string
					switch x := m.(type) {
					case *ast.FuncLit:
						k := s.Pkg + " closure at " + fset.Position(x.Pos()).String()
						if _, seen := bodies[k]; !seen {
							bodies[k] = &body{key: k, node: x, pkg: s.Pkg}
						}
						keys = []string{k}
					case *ast.SelectorExpr:
						keys = bodyKeys(decls, s.Pkg+"."+x.Sel.Name)
					case *ast.Ident:
						keys = bodyKeys(decls, s.Pkg+"."+x.Name)
					}
					for _, k := range keys {
						r.Handlers = append(r.Handlers, k)
						if available[k] == nil {
							available[k] = map[string]bool{}
						}
						for _, p := range r.Params {
							available[k][p] = true
						}
						routesOf[k] = appendUnique(routesOf[k], label)
					}
					return true
				})
			}
			r.Handlers = appendUniqueAll(nil, r.Handlers)
			res.Routes = append(res.Routes, r)
			if len(r.Handlers) == 0 && len(r.Params) > 0 {
				res.Blind = append(res.Blind, r)
			}
			return true
		})
	}

	// Propagate to a fixpoint: a handler's parameters are available to every
	// same-package function it calls, because the *gin.Context it holds is the
	// one those functions read. Twelve rounds is far past the depth of any
	// handler here and stops a pathological cycle from spinning.
	for round := 0; round < 12; round++ {
		changed := false
		for key, b := range bodies {
			avail := available[key]
			if avail == nil {
				continue
			}
			ast.Inspect(b.node, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch x := ce.Fun.(type) {
				case *ast.SelectorExpr:
					name = x.Sel.Name
				case *ast.Ident:
					name = x.Name
				default:
					return true
				}
				for _, ck := range bodyKeys(decls, b.pkg+"."+name) {
					if ck == key {
						continue
					}
					if available[ck] == nil {
						available[ck] = map[string]bool{}
					}
					for p := range avail {
						if !available[ck][p] {
							available[ck][p] = true
							changed = true
						}
					}
					for _, label := range routesOf[key] {
						if grown := appendUnique(routesOf[ck], label); len(grown) != len(routesOf[ck]) {
							routesOf[ck] = grown
							changed = true
						}
					}
				}
				return true
			})
		}
		if !changed {
			break
		}
	}

	// Finding 1: a parameter name no reaching route declares.
	seen := map[string]bool{}
	for key, b := range bodies {
		avail := available[key]
		if avail == nil {
			continue // unreachable body; finding 2 is what covers it
		}
		ast.Inspect(b.node, func(n ast.Node) bool {
			name, lit := paramRead(n)
			if lit == nil || avail[name] {
				return true
			}
			pos := fset.Position(lit.Pos())
			id := fmt.Sprintf("%s:%d:%s", pos.Filename, pos.Line, name)
			if seen[id] {
				return true
			}
			seen[id] = true
			declared := sortedKeys(avail)
			routes := append([]string(nil), routesOf[key]...)
			sort.Strings(routes)
			res.Params = append(res.Params, paramFinding{
				Func: key, Name: name, File: pos.Filename, Line: pos.Line,
				Declared: declared, Routes: routes,
			})
			return true
		})
	}
	sort.Slice(res.Params, func(i, j int) bool {
		if res.Params[i].File != res.Params[j].File {
			return res.Params[i].File < res.Params[j].File
		}
		return res.Params[i].Line < res.Params[j].Line
	})

	// Finding 2: a handler-shaped function nothing references.
	uses := map[string]int{}
	for _, s := range srcs {
		countUses(s.Pkg, s.File, uses)
	}
	for _, s := range srcs {
		for _, d := range s.File.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !isHandlerShaped(fset, fd) {
				continue
			}
			res.HandlerShaped++
			key := s.Pkg + "." + fd.Name.Name
			if uses[key] > 0 {
				continue
			}
			pos := fset.Position(fd.Pos())
			res.Unmounted = append(res.Unmounted, unmountedFinding{Key: key, File: pos.Filename, Line: pos.Line})
		}
	}
	sort.Slice(res.Unmounted, func(i, j int) bool {
		if res.Unmounted[i].File != res.Unmounted[j].File {
			return res.Unmounted[i].File < res.Unmounted[j].File
		}
		return res.Unmounted[i].Line < res.Unmounted[j].Line
	})

	sort.Slice(res.Routes, func(i, j int) bool {
		if res.Routes[i].Path != res.Routes[j].Path {
			return res.Routes[i].Path < res.Routes[j].Path
		}
		return res.Routes[i].Method < res.Routes[j].Method
	})
	return res
}

// groupPaths returns the string literal of every .Group(...) call in a file.
//
// The param check is sound only while no group prefix declares a parameter of
// its own -- otherwise a route's own path is not the whole source of its names.
// That holds in this tree, and the self-test asserts it against the real
// sources rather than trusting this comment.
func groupPaths(s source) []string {
	var out []string
	ast.Inspect(s.File, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Group" {
			return true
		}
		lit, ok := ce.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if p, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, p)
		}
		return true
	})
	return out
}

// paramRead recognises c.Param("name") and returns the literal.
func paramRead(n ast.Node) (string, *ast.BasicLit) {
	ce, ok := n.(*ast.CallExpr)
	if !ok {
		return "", nil
	}
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Param" || len(ce.Args) != 1 {
		return "", nil
	}
	lit, ok := ce.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", nil
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", nil
	}
	return name, lit
}

// isHandlerShaped reports whether fd has gin.HandlerFunc's signature: one
// *gin.Context parameter and no results. That is the shape a route mounts, and
// the only shape whose absence from the route table means anything.
func isHandlerShaped(fset *token.FileSet, fd *ast.FuncDecl) bool {
	if fd.Body == nil {
		return false
	}
	if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
		return false
	}
	params := fd.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		return false
	}
	return exprString(fset, params[0].Type) == "*gin.Context"
}

// countUses records every identifier and selector name a file mentions, except
// the names of the functions it declares. A function nothing mentions is one
// nothing can call.
func countUses(pkg string, f *ast.File, uses map[string]int) {
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.SelectorExpr:
				uses[pkg+"."+x.Sel.Name]++
			case *ast.Ident:
				uses[pkg+"."+x.Name]++
			}
			return true
		})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fd.Recv != nil {
			walk(fd.Recv)
		}
		walk(fd.Type)
		if fd.Body != nil {
			walk(fd.Body)
		}
		return false
	})
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return b.String()
}

func bodyKey(declKey string, i int) string {
	if i == 0 {
		return declKey
	}
	return fmt.Sprintf("%s#%d", declKey, i)
}

func bodyKeys(decls map[string][]*ast.FuncDecl, declKey string) []string {
	ds, ok := decls[declKey]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(ds))
	for i := range ds {
		out = append(out, bodyKey(declKey, i))
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

func appendUniqueAll(list, add []string) []string {
	for _, s := range add {
		list = appendUnique(list, s)
	}
	return list
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
