// Command posturevocab reports which posture checks each client can actually
// perform, per operating system, and fails when two clients claim the same
// check on the same platform.
//
// Usage:
//
//	posturevocab [-fail] [-census]
//
// WHY. The product ships two things that report device posture to the same
// endpoint under the same check_type vocabulary: the Go engine (agent/, hosted
// as the desktop service and embedded in the companion app by gomobile) and
// the Kotlin agent (agent-android/, for managed devices). Nothing held the two
// vocabularies next to each other, and the gap that opened is the reason this
// tool exists.
//
// Seven of the Go engine's ten checks dispatch on runtime.GOOS with cases for
// linux, darwin and windows only. On the gomobile builds — GOOS=android and
// GOOS=ios, which is what the companion app is — those seven answered
// StatusWarn "not supported on android" without examining anything, and the
// engine's compliance sum ignored warns. A phone whose disk encryption
// (severity: critical) had never been looked at was reported COMPLIANT, in
// green, on its owner's home screen.
//
// That defect was invisible to every other check in this repository: the code
// compiles for Android, the tests pass on the Linux runner where those same
// checks take a real branch, the JSON is well-formed, and "0 failures" is
// true of a device nobody examined. Only holding coverage next to platform
// can see it.
//
// WHAT IT DERIVES. Both halves come from the tree, never from a list someone
// maintains:
//
//   - Go: the check names registered in agent/ (registry.Register calls), and
//     for each, the platforms it can examine — derived from where the check
//     DECLINES, that is from the branch that returns a result with
//     `Unsupported: true`. A check that never declines is
//     platform-independent and covers everything.
//   - Kotlin: the `override val checkType` values in agent-android/, all of
//     which are Android by construction.
//
// TWO FINDINGS:
//
//	claimed twice   one check_type that both clients implement for the SAME
//	                platform. Two implementations of one word, in two
//	                languages, reporting to one column: they will drift, and
//	                nothing else would notice when they do.
//	covered nowhere a check_type some client knows about that no client can
//	                perform on a platform the product ships to.
//
// Findings are registered in known.go with a verdict apiece. A finding absent
// from the register fails the run; a register entry that no longer reproduces
// fails it too, so the register can only shrink — the shape tools/tablewriters
// and the syssettings census use, for the same reason.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// shippedPlatforms are the operating systems a client of this product runs on.
// The Go engine targets the first three as a service and the last two through
// gomobile; the Kotlin agent targets android.
var shippedPlatforms = []string{"windows", "darwin", "linux", "android", "ios"}

type coverage struct {
	// platforms the implementation actually covers.
	platforms map[string]bool
	// where it came from, for the report.
	source string
}

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 on an unregistered finding")
	census := flag.Bool("census", false, "print the full coverage matrix")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	goChecks, err := scanGoChecks(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "posturevocab: %v\n", err)
		os.Exit(2)
	}
	kotlinChecks, err := scanKotlinChecks(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "posturevocab: %v\n", err)
		os.Exit(2)
	}
	if len(goChecks) == 0 {
		fmt.Fprintln(os.Stderr, "posturevocab: found no Go checks at all — the scan is not reading the tree")
		os.Exit(2)
	}

	if *census {
		printCensus(goChecks, kotlinChecks)
		return
	}

	findings := report(goChecks, kotlinChecks)

	found := map[string]bool{}
	for _, f := range findings {
		found[f.key()] = true
	}
	var stale []string
	for key := range knownFindings {
		if !found[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	var unregistered []finding
	for _, f := range findings {
		if _, ok := knownFindings[f.key()]; !ok {
			unregistered = append(unregistered, f)
		}
	}

	for _, f := range unregistered {
		fmt.Printf("%s\n", f.describe())
	}
	for _, key := range stale {
		fmt.Printf("%s: registered as a finding, but it no longer reproduces\n", key)
		fmt.Printf("    remove its entry from tools/posturevocab/known.go\n")
	}

	fmt.Fprintf(os.Stderr, "posturevocab: %d Go check(s), %d Kotlin check(s), %d finding(s) (%d registered, %d new, %d stale)\n",
		len(goChecks), len(kotlinChecks), len(findings), len(knownFindings), len(unregistered), len(stale))

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0) {
		os.Exit(1)
	}
}

type finding struct {
	Kind      string // "claimed_twice" | "covered_nowhere"
	CheckType string
	Platform  string
	Detail    string
}

func (f finding) key() string { return f.Kind + ":" + f.CheckType + ":" + f.Platform }

func (f finding) describe() string {
	switch f.Kind {
	case "claimed_twice":
		return fmt.Sprintf("%s on %s: implemented by BOTH clients\n"+
			"    %s\n"+
			"    Two implementations of one check_type, in two languages, reporting to one\n"+
			"    column. They will drift, and the server cannot tell which one answered.",
			f.CheckType, f.Platform, f.Detail)
	default:
		return fmt.Sprintf("%s on %s: no client can perform it\n    %s", f.CheckType, f.Platform, f.Detail)
	}
}

func report(goChecks, kotlinChecks map[string]coverage) []finding {
	var out []finding

	all := map[string]bool{}
	for name := range goChecks {
		all[name] = true
	}
	for name := range kotlinChecks {
		all[name] = true
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		g, hasGo := goChecks[name]
		k, hasKotlin := kotlinChecks[name]
		for _, plat := range shippedPlatforms {
			goCovers := hasGo && g.platforms[plat]
			ktCovers := hasKotlin && k.platforms[plat]
			if goCovers && ktCovers {
				out = append(out, finding{
					Kind: "claimed_twice", CheckType: name, Platform: plat,
					Detail: fmt.Sprintf("Go: %s   Kotlin: %s", g.source, k.source),
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func printCensus(goChecks, kotlinChecks map[string]coverage) {
	all := map[string]bool{}
	for n := range goChecks {
		all[n] = true
	}
	for n := range kotlinChecks {
		all[n] = true
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Printf("%-22s %-9s %-8s %-7s %-9s %-5s  source\n", "check_type", "windows", "darwin", "linux", "android", "ios")
	for _, name := range names {
		g, hasGo := goChecks[name]
		k, hasKotlin := kotlinChecks[name]
		cell := func(plat string) string {
			var who []string
			if hasGo && g.platforms[plat] {
				who = append(who, "go")
			}
			if hasKotlin && k.platforms[plat] {
				who = append(who, "kt")
			}
			if len(who) == 0 {
				return "-"
			}
			return strings.Join(who, "+")
		}
		src := ""
		if hasGo {
			src = g.source
		}
		if hasKotlin {
			if src != "" {
				src += ", "
			}
			src += k.source
		}
		fmt.Printf("%-22s %-9s %-8s %-7s %-9s %-5s  %s\n",
			name, cell("windows"), cell("darwin"), cell("linux"), cell("android"), cell("ios"), src)
	}
}

var reRegister = regexp.MustCompile(`\.Register\("([a-z_]+)",\s*&checks\.(\w+)\{\}\)`)

// scanGoChecks finds every check the Go agent registers and works out which
// platforms each one implements.
func scanGoChecks(root string) (map[string]coverage, error) {
	agentDir := filepath.Join(root, "agent")

	// Which type implements which registered name.
	typeForName := map[string]string{}
	err := filepath.Walk(agentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, m := range reRegister.FindAllStringSubmatch(string(b), -1) {
			typeForName[m[1]] = m[2]
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", agentDir, err)
	}

	// Which platforms each type's Run method dispatches to.
	platformsForType, sourceForType, err := scanGoPlatforms(filepath.Join(agentDir, "internal", "checks"))
	if err != nil {
		return nil, err
	}

	out := map[string]coverage{}
	for name, typ := range typeForName {
		plats, known := platformsForType[typ]
		if !known {
			// No GOOS switch: the check is platform-independent.
			plats = map[string]bool{}
			for _, p := range shippedPlatforms {
				plats[p] = true
			}
		}
		src := sourceForType[typ]
		if src == "" {
			src = typ
		}
		out[name] = coverage{platforms: plats, source: src}
	}
	return out, nil
}

// scanGoPlatforms reads the checks package and works out, for every check
// type, which operating systems it can actually examine.
//
// Coverage is derived from where the check DECLINES, not from where it
// dispatches. `Unsupported: true` is the one explicit, greppable claim "I have
// no implementation here"; a `case "linux":` label only says a branch exists.
// The first draft of this tool read case labels and, the moment a check was
// fixed to decline on android by naming android in a case, reported android as
// covered — the inversion of the truth.
//
// Three declining shapes appear in the tree. Anything else fails the run
// rather than being guessed at: a coverage map that silently mis-reads a new
// shape is worse than no map.
//
//	switch runtime.GOOS { case A, B: <decline> }        -> A and B uncovered
//	switch runtime.GOOS { case A: ...; default: <decline> } -> all but A uncovered
//	if runtime.GOOS != "A" { <decline> }                -> all but A uncovered
func scanGoPlatforms(dir string) (map[string]map[string]bool, map[string]string, error) {
	plats := map[string]map[string]bool{}
	src := map[string]string{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, perr)
		}

		var walkErr error
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				return true
			}
			recv := receiverType(fn.Recv)
			if recv == "" {
				return true
			}
			if _, seen := src[recv]; !seen {
				src[recv] = e.Name()
			}
			declined, derr := decliningPlatforms(fn.Body)
			if derr != nil {
				walkErr = fmt.Errorf("%s: %s: %w", e.Name(), fn.Name.Name, derr)
				return false
			}
			if declined == nil {
				return true
			}
			if plats[recv] == nil {
				plats[recv] = map[string]bool{}
				for _, p := range shippedPlatforms {
					plats[recv][p] = true
				}
			}
			for p := range declined {
				delete(plats[recv], p)
			}
			return true
		})
		if walkErr != nil {
			return nil, nil, walkErr
		}
	}
	return plats, src, nil
}

// decliningPlatforms returns the operating systems on which body refuses to
// answer, or nil when it never refuses.
//
// An unrecognised declining shape is an ERROR, never a guess, and that is
// enforced by accounting rather than asserted: every `Unsupported: true` in
// the body must be claimed by one of the three recognised shapes. A declining
// branch this function cannot read would otherwise leave the check looking
// fully covered — the coverage map would say a platform is examined when the
// code has just been changed to say it is not, which is the precise failure
// the map exists to prevent.
func decliningPlatforms(body *ast.BlockStmt) (map[string]bool, error) {
	var out map[string]bool
	var err error
	claimed := map[token.Pos]bool{}

	ast.Inspect(body, func(n ast.Node) bool {
		if err != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.SwitchStmt:
			if !isGOOSSwitch(node.Tag) {
				return true
			}
			var named []string
			var defaultDeclines bool
			var caseDeclines []string
			for _, stmt := range node.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				labels := caseLabels(cc)
				named = append(named, labels...)
				pos := unsupportedPositions(cc.Body)
				if len(pos) == 0 {
					continue
				}
				for _, p := range pos {
					claimed[p] = true
				}
				if len(cc.List) == 0 {
					defaultDeclines = true
				} else {
					caseDeclines = append(caseDeclines, labels...)
				}
			}
			if defaultDeclines {
				if out == nil {
					out = map[string]bool{}
				}
				for p := range complementOf(named) {
					out[p] = true
				}
			}
			for _, p := range caseDeclines {
				if out == nil {
					out = map[string]bool{}
				}
				out[p] = true
			}
			return true

		case *ast.IfStmt:
			pos := unsupportedPositions(node.Body.List)
			if len(pos) == 0 {
				return true
			}
			bin, ok := node.Cond.(*ast.BinaryExpr)
			if !ok || !isGOOSSwitch(bin.X) {
				// Leave it unclaimed; the accounting below reports it.
				return true
			}
			lit, ok := bin.Y.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if out == nil {
				out = map[string]bool{}
			}
			switch bin.Op {
			case token.NEQ: // runtime.GOOS != "linux": everything else declines
				for p := range complementOf([]string{v}) {
					out[p] = true
				}
			case token.EQL: // runtime.GOOS == "android": that one declines
				out[v] = true
			default:
				return true // unclaimed; reported below
			}
			for _, p := range pos {
				claimed[p] = true
			}
			return true
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	for _, p := range unsupportedPositions(body.List) {
		if !claimed[p] {
			return nil, fmt.Errorf("an Unsupported result at offset %d is not guarded by a "+
				"recognised runtime.GOOS shape, so the platforms it declines on cannot be "+
				"derived. Use `switch runtime.GOOS` with a declining case or default, or "+
				"`if runtime.GOOS != \"x\"`, or teach this tool the new shape", p)
		}
	}
	return out, nil
}

// unsupportedPositions returns the position of every `Unsupported: true` in
// stmts, so a declining branch can be accounted for rather than merely
// detected.
func unsupportedPositions(stmts []ast.Stmt) []token.Pos {
	var out []token.Pos
	for _, s := range stmts {
		ast.Inspect(s, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Unsupported" {
				return true
			}
			if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
				out = append(out, kv.Pos())
			}
			return true
		})
	}
	return out
}

func caseLabels(cc *ast.CaseClause) []string {
	var out []string
	for _, expr := range cc.List {
		if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

func complementOf(named []string) map[string]bool {
	in := map[string]bool{}
	for _, n := range named {
		in[n] = true
	}
	out := map[string]bool{}
	for _, p := range shippedPlatforms {
		if !in[p] {
			out[p] = true
		}
	}
	return out
}

func receiverType(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	switch t := fl.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// isGOOSSwitch reports whether expr is the identifier runtime.GOOS.
func isGOOSSwitch(tag ast.Expr) bool {
	sel, ok := tag.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "GOOS" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "runtime"
}

var reKotlinCheckType = regexp.MustCompile(`override val checkType: String = "([a-z_]+)"`)

// scanKotlinChecks finds the check types the Android agent implements. They
// are Android-only by construction: the module is an Android application.
func scanKotlinChecks(root string) (map[string]coverage, error) {
	dir := filepath.Join(root, "agent-android")
	out := map[string]coverage{}
	if _, err := os.Stat(dir); err != nil {
		// The Android agent may be absent from a trimmed checkout; that is not
		// a finding, it just means there is nothing to compare against.
		return out, nil
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".kt") {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, m := range reKotlinCheckType.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = coverage{
				platforms: map[string]bool{"android": true},
				source:    filepath.Base(path),
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	return out, nil
}
