// Command inertswitch finds request switches that decide nothing.
//
// Usage:
//
//	inertswitch [-fail] [-census] [package...]
//
// THE SHAPE. `POST /temp-access` accepted `require_mfa` and `notify_on_use`.
// Both were bound from the request body, stored in their column, selected back
// into the struct on every read, and returned to the console, which rendered a
// switch for each. Neither was ever compared to anything. Turning `require_mfa`
// on did not require MFA. Turning `notify_on_use` on notified nobody. The
// public-surface register — the guard that makes every anonymously reachable
// route carry a written justification — listed MFA among the checks that route
// performed, so the guard vouched for the switch as well.
//
// A switch that does nothing is worse than an absent one, because the operator
// who set it believes something changed, and so does everyone reading the
// register afterwards. It is invisible to everything else here:
//
//   - it binds and type-checks, so the compiler is happy;
//   - it round-trips through the database, so no nil or zero-value check fires;
//   - the console renders it, so the UI tests pass;
//   - tools/deadconfig does not see it — that census asks whether a field has a
//     READER, and this field has several: the INSERT reads it, the Scan writes
//     it, the JSON response reads it. What it never has is a DECIDER.
//
// WHY THE SET IS DERIVED. The settable half is every field of every struct this
// tree binds from a request body (ShouldBindJSON and friends) — which is exactly
// what an API caller can set. Not a list someone maintains: a list nobody
// remembered to add to is not unchecked in a way anyone can see, it is
// invisible, which is the property that made tools/orgscope wrong until it was
// inverted.
//
// BOOLS ONLY, and that is the narrowest and least arguable form of the question.
// A bool a caller can set is a claim about behaviour: there is no other reason
// to accept one. A string can honestly be data — a name, a description — that
// the product stores and displays and never decides on, so silence about a
// string is not by itself a lie. `notify_email` on that same row was the string
// case, and the argument that retired it was different (the notification service
// is keyed by user id, so there was no sender that could ever have delivered to
// it). This census does not attempt that argument.
//
// WHAT COUNTS AS DECIDING. A use of the field in a condition, a comparison, a
// negation, a switch tag or case, or as an argument to any call other than a
// database store. Passing it to a helper counts as deciding: the helper may be
// where the decision lives, and reporting it would be a false positive on the
// most common honest shape. So this errs heavily towards silence — a reported
// field is one where nothing in the product so much as tests it.
//
// TRANSFERS ARE FOLLOWED. A request field is nearly always copied into a model
// struct before it reaches SQL (CreateTempAccessRequest.NotifyOnUse into
// TempAccessLink.NotifyOnUse), so an assignment from one field to another is an
// edge, and a request field is decided if anything it flows into is decided.
// Without that every request bool would be reported, and a gate that fails
// everything is as useless as one that fails nothing.
//
// TESTS ARE NOT DECIDERS. Test files are not loaded. A switch only a test
// compares is a switch the product does not consult, and the test is asserting
// the plumbing rather than the effect — which is exactly how `require_mfa` kept
// its passing round-trip test while requiring nothing.
//
// TWO BLIND SPOTS, AND WHAT IS DONE ABOUT THEM. A value can leave Go and come
// back, and this analysis cannot follow it:
//
//  1. THROUGH THE DATABASE. The usual shape is request → column → a DIFFERENT
//     struct loaded by a different query, where the decision lives.
//     pamEntryUpsertReq.RecordSession is stored; pamLaunchEntry.RecordSession is
//     loaded and decided on; no Go assignment connects them. So a switch is
//     suppressed when a field of the same name IN THE SAME PACKAGE is decided.
//     That is name matching, which tools/deadconfig rejects for good reason —
//     but there it accuses and here it only excuses, so a collision costs a
//     missed finding rather than a false one. The package qualifier is not
//     decoration: internal/oauth decides on a field called RequireMFA, so a
//     bare-name rule excused internal/access's require_mfa — the switch this
//     tool was built for.
//  2. IN SQL. `WHERE enabled = true` is a decision the type checker cannot see.
//     So a switch is suppressed when its column name appears after a WHERE in
//     any query in the tree. Same direction: it can only hide a finding.
//
// Both make the census quieter than the truth. That is the right way round for
// a gate that blocks a merge, and it is why the register below is expected to
// be empty rather than long: what survives both suppressions is a switch nothing
// anywhere — Go or SQL, this struct or any other — ever looks at.
//
// Findings are registered in known.go with a verdict apiece. A finding absent
// from the register fails the run; an entry that no longer reproduces fails it
// too, so the register can only shrink.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// defaultPatterns is the whole module. The binding half is a few dozen handler
// files, but the DECIDING half is every package: loading only the handlers would
// find no deciders and report every switch.
var defaultPatterns = []string{"./..."}

// binders are the gin methods that fill a struct from what the caller sent.
// Anything reached this way is, by definition, settable from outside.
var binders = map[string]bool{
	"ShouldBindJSON": true, "ShouldBind": true, "ShouldBindQuery": true,
	"ShouldBindUri": true, "ShouldBindWith": true, "ShouldBindBodyWith": true,
	"BindJSON": true, "Bind": true, "BindQuery": true, "BindUri": true,
}

// storeMethods are the database calls a field's value legitimately ends in
// without anything having decided on it. Everything else that takes the field as
// an argument is treated as a possible decider.
var storeMethods = map[string]bool{
	"Exec": true, "Query": true, "QueryRow": true, "Scan": true,
	"SendBatch": true, "CopyFrom": true, "QueryRowContext": true,
	"ExecContext": true, "QueryContext": true,
}

// aSwitch is one bool field a caller can set.
type aSwitch struct {
	Key    string // "access.CreateTempAccessRequest.NotifyOnUse" — the register key
	JSON   string // the wire name, what the caller writes
	Struct string
	Pkg    string
	Decl   token.Pos
	Pos    token.Position
}

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 on a switch nothing decides on")
	census := flag.Bool("census", false, "print every request switch and whether anything decides on it")
	flag.Parse()

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = defaultPatterns
	}

	switches, decided, excused, err := analyze(patterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inertswitch: %v\n", err)
		os.Exit(2)
	}
	for pos := range excused {
		decided[pos] = true
	}
	if len(switches) == 0 {
		// A census that found nothing to census has not proved the tree is
		// clean, it has proved it did not load.
		fmt.Fprintf(os.Stderr, "inertswitch: no bool fields on request-bound structs found in %v; "+
			"the load found nothing to check\n", patterns)
		os.Exit(2)
	}

	var findings []aSwitch
	for _, s := range switches {
		if !decided[s.Decl] {
			findings = append(findings, s)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Key < findings[j].Key })

	if *census {
		printCensus(switches, decided)
		return
	}

	byKey := map[string]aSwitch{}
	for _, f := range findings {
		byKey[f.Key] = f
	}
	var unregistered []aSwitch
	for _, f := range findings {
		if _, ok := knownInert[f.Key]; !ok {
			unregistered = append(unregistered, f)
		}
	}
	var stale []string
	for key := range knownInert {
		if _, ok := byKey[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	fmt.Printf("inertswitch: %d request switches, %d decided, %d inert (%d registered)\n",
		len(switches), len(switches)-len(findings), len(findings), len(knownInert))

	for _, f := range unregistered {
		fmt.Printf("\nNEW  %s\n", f.Key)
		fmt.Printf("     %s\n", f.Pos)
		fmt.Printf("     a caller can set %q and nothing in the product decides on it\n", f.JSON)
	}
	for _, key := range stale {
		fmt.Printf("\nSTALE %s — registered as inert, and something decides on it now. "+
			"Delete its line in tools/inertswitch/known.go.\n", key)
	}

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0) {
		os.Exit(1)
	}
}

func printCensus(switches []aSwitch, decided map[token.Pos]bool) {
	sort.Slice(switches, func(i, j int) bool { return switches[i].Key < switches[j].Key })
	for _, s := range switches {
		state := "inert"
		if decided[s.Decl] {
			state = "decided"
		}
		fmt.Printf("%-8s %-64s %s\n", state, s.Key, s.JSON)
	}
}

// analyze loads the packages and returns every bool field of a request-bound
// struct together with the set of field objects something decides on, keyed by
// declaration position — unique across the shared FileSet and identical between
// the Defs entry that declares a field and every Uses entry that reads it.
func analyze(patterns []string) (switches []aSwitch, decided, excused map[token.Pos]bool, err error) {
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Fset: fset,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports | packages.NeedModule,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load: %w", err)
	}
	var loadErr error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			// A package that failed to type-check yields no Uses, so every one
			// of its switches would be reported inert. Refuse rather than lie.
			if strings.Contains(e.Msg, "build constraints exclude all Go files") {
				continue
			}
			if loadErr == nil {
				loadErr = fmt.Errorf("%s: %v", p.PkgPath, e)
			}
		}
	})
	if loadErr != nil {
		return nil, nil, nil, loadErr
	}

	bound := boundTypes(pkgs)
	switches = declaredSwitches(pkgs, fset, bound)

	direct, edges := classifyUses(pkgs)

	// A field is decided if anything decides on it, or on anything it flows
	// into. Fixpoint rather than one hop: a request field can be copied into a
	// model and from there into a second model.
	decided = map[token.Pos]bool{}
	for pos := range direct {
		decided[pos] = true
	}
	for changed := true; changed; {
		changed = false
		for from, targets := range edges {
			if decided[from] {
				continue
			}
			for _, to := range targets {
				if decided[to] {
					decided[from] = true
					changed = true
					break
				}
			}
		}
	}
	// The two blind spots, both suppressive only. See the package comment.
	// Keyed by package AND name, not by name alone. The round trip this excuses
	// is a request struct and the model its own feature loads back —
	// pamEntryUpsertReq.RecordSession and pamLaunchEntry.RecordSession, both in
	// internal/access. A bare name reaches across the whole tree, and there it
	// hides the case this tool exists for: internal/oauth decides on a field
	// called RequireMFA, so a bare-name rule excuses access's require_mfa, which
	// was stored and never once compared.
	decidedNames := map[string]bool{}
	predicates := sqlPredicateColumns(pkgs)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, obj := range p.TypesInfo.Uses {
			v, ok := obj.(*types.Var)
			if ok && v.IsField() && decided[v.Pos()] && v.Pkg() != nil {
				decidedNames[v.Pkg().Path()+"."+v.Name()] = true
			}
		}
	})

	excused = map[token.Pos]bool{}
	for _, s := range switches {
		if decided[s.Decl] {
			continue
		}
		if decidedNames[s.Pkg+"."+fieldName(s.Key)] {
			excused[s.Decl] = true
			continue
		}
		if predicates[s.JSON] {
			excused[s.Decl] = true
		}
	}

	return switches, decided, excused, nil
}

// fieldName is the last dotted component of a register key.
func fieldName(key string) string {
	parts := strings.Split(key, ".")
	return parts[len(parts)-1]
}

// sqlPredicateColumns is every column name that appears after a WHERE in a
// query somewhere in the tree — a decision the type checker cannot see. Names
// before the WHERE are the SET and column lists of a write, which decide
// nothing.
func sqlPredicateColumns(pkgs []*packages.Package) map[string]bool {
	cols := map[string]bool{}
	word := regexp.MustCompile(`[a-z_][a-z0-9_]*`)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text := strings.ToLower(lit.Value)
				idx := strings.Index(text, "where")
				if idx < 0 {
					return true
				}
				for _, w := range word.FindAllString(text[idx:], -1) {
					cols[w] = true
				}
				return true
			})
		}
	})
	return cols
}

// boundTypes is the set of named struct types this tree fills from a request
// body: the type of the argument to a binder call, with the pointer stripped.
func boundTypes(pkgs []*packages.Package) map[string]bool {
	bound := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !binders[sel.Sel.Name] {
					return true
				}
				for _, arg := range call.Args {
					if name := namedOf(p.TypesInfo.TypeOf(arg)); name != "" {
						bound[name] = true
					}
				}
				return true
			})
		}
	})
	return bound
}

// namedOf resolves a type to its named struct, through pointers, or "" when it
// is not one.
func namedOf(t types.Type) string {
	if t == nil {
		return ""
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return ""
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// declaredSwitches lists the bool fields of every request-bound struct.
func declaredSwitches(pkgs []*packages.Package, fset *token.FileSet, bound map[string]bool) []aSwitch {
	var out []aSwitch
	seen := map[token.Pos]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			if strings.HasSuffix(fset.Position(file.Pos()).Filename, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				if !bound[p.PkgPath+"."+ts.Name.Name] {
					return true
				}
				for _, f := range st.Fields.List {
					if !isBool(p.TypesInfo.TypeOf(f.Type)) {
						continue
					}
					for _, name := range f.Names {
						obj, ok := p.TypesInfo.Defs[name].(*types.Var)
						if !ok || seen[obj.Pos()] {
							continue
						}
						seen[obj.Pos()] = true
						out = append(out, aSwitch{
							Key:    shortPkg(p.PkgPath) + "." + ts.Name.Name + "." + name.Name,
							JSON:   jsonTag(f.Tag, name.Name),
							Struct: ts.Name.Name,
							Pkg:    p.PkgPath,
							Decl:   obj.Pos(),
							Pos:    fset.Position(obj.Pos()),
						})
					}
				}
				return true
			})
		}
	})
	return out
}

func isBool(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// classifyUses walks every use of every field and returns the fields something
// decides on directly, plus the transfer edges (this field's value was assigned
// to that field).
func classifyUses(pkgs []*packages.Package) (direct map[token.Pos]bool, edges map[token.Pos][]token.Pos) {
	direct = map[token.Pos]bool{}
	edges = map[token.Pos][]token.Pos{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			// parents maps each node to its enclosing node, so a use can be
			// classified by where it sits rather than by what it looks like.
			parents := map[ast.Node]ast.Node{}
			var stack []ast.Node
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					if len(stack) > 0 {
						stack = stack[:len(stack)-1]
					}
					return true
				}
				if len(stack) > 0 {
					parents[n] = stack[len(stack)-1]
				}
				stack = append(stack, n)
				return true
			})

			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj, ok := p.TypesInfo.Uses[sel.Sel].(*types.Var)
				if !ok || !obj.IsField() {
					return true
				}
				if target := transferTarget(p, parents, sel); target != token.NoPos {
					edges[obj.Pos()] = append(edges[obj.Pos()], target)
					return true
				}
				if decidesHere(p, parents, sel) {
					direct[obj.Pos()] = true
				}
				return true
			})
		}
	})
	return direct, edges
}

// transferTarget reports the field this use is being copied into — the RHS of
// `x.A = y.B`, or the value of `T{A: y.B}` — or NoPos when the use is not a
// plain copy.
func transferTarget(p *packages.Package, parents map[ast.Node]ast.Node, use *ast.SelectorExpr) token.Pos {
	switch parent := parents[use].(type) {
	case *ast.KeyValueExpr:
		if parent.Value != ast.Expr(use) {
			return token.NoPos
		}
		if key, ok := parent.Key.(*ast.Ident); ok {
			if obj, ok := p.TypesInfo.Uses[key].(*types.Var); ok && obj.IsField() {
				return obj.Pos()
			}
		}
	case *ast.AssignStmt:
		if parent.Tok != token.ASSIGN && parent.Tok != token.DEFINE {
			return token.NoPos
		}
		for i, rhs := range parent.Rhs {
			if rhs != ast.Expr(use) || i >= len(parent.Lhs) {
				continue
			}
			lhs, ok := parent.Lhs[i].(*ast.SelectorExpr)
			if !ok {
				return token.NoPos
			}
			if obj, ok := p.TypesInfo.Uses[lhs.Sel].(*types.Var); ok && obj.IsField() {
				return obj.Pos()
			}
		}
	}
	return token.NoPos
}

// decidesHere reports whether this use is somewhere a value can change what the
// product does. Anything not recognised as a pure store counts as deciding: the
// cost of a false negative here is one unreported switch, the cost of a false
// positive is a gate nobody trusts.
func decidesHere(p *packages.Package, parents map[ast.Node]ast.Node, use *ast.SelectorExpr) bool {
	var node ast.Node = use
	for depth := 0; depth < 32; depth++ {
		parent, ok := parents[node]
		if !ok {
			return false
		}
		switch pn := parent.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.CaseClause,
			*ast.BinaryExpr, *ast.UnaryExpr, *ast.TypeSwitchStmt, *ast.RangeStmt,
			*ast.IndexExpr, *ast.ReturnStmt, *ast.SelectorExpr:
			return true
		case *ast.CallExpr:
			// A store is the one call that decides nothing. Everything else may
			// decide inside, so it counts.
			if sel, ok := pn.Fun.(*ast.SelectorExpr); ok && storeMethods[sel.Sel.Name] {
				return false
			}
			return true
		case *ast.KeyValueExpr, *ast.CompositeLit, *ast.AssignStmt:
			// A copy into something that is not a field — a map entry, a slice,
			// a local. Follow it up rather than judging here; the enclosing
			// expression says what it is for.
			node = parent
		default:
			node = parent
		}
		_ = p
	}
	return true
}

func jsonTag(tag *ast.BasicLit, fallback string) string {
	if tag == nil {
		return fallback
	}
	value := strings.Trim(tag.Value, "`")
	name := reflect.StructTag(value).Get("json")
	if name == "" {
		return fallback
	}
	if comma := strings.Index(name, ","); comma >= 0 {
		name = name[:comma]
	}
	if name == "" || name == "-" {
		return fallback
	}
	return name
}

func shortPkg(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}
