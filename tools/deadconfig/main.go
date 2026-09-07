// Command deadconfig finds configuration fields nothing reads.
//
// Usage:
//
//	deadconfig [-fail] [-census] [package...]
//
// THE SHAPE. internal/gateway.Config has carried EnableRateLimit (default true)
// and a RateLimitConfig of 100 requests a minute since the gateway was written.
// An operator setting GATEWAY_RATE_LIMIT_RPM got a value that was parsed,
// defaulted, logged at startup and stored on the config struct — and no router
// ever mounted the limiter, so the internet-facing service answered unbounded.
// ENABLE_MFA and ENABLE_AUDIT_LOGGING were the same thing with the switch the
// other way round: a field, a default, and a line each in a shipped config file,
// read by nothing. `ENABLE_MFA=false` got you MFA.
//
// A setting that is silently ignored is worse than one that was never offered,
// because the operator who set it believes something changed. It is also
// invisible to every other check this repository has:
//
//   - the field parses and type-checks, so the compiler is happy;
//   - viper's default makes it non-zero, so no nil or empty-value check fires;
//   - the docs describe it, which is prose, so no test reads that;
//   - nothing fails at runtime — the product does what it did before.
//
// The only thing that can see it is a census: hold the set of fields an operator
// can set next to the set of fields the code reads, and subtract.
//
// WHY THE SET IS DERIVED. Both halves come from the tree. The settable half is
// every struct field carrying a `mapstructure` tag in the packages scanned —
// which is what viper binds, so it is exactly what an operator can put in a
// config file or an environment variable. The read half comes from the type
// checker. A list of "fields to check" would have the property that made
// tools/orgscope wrong before it was inverted: a field nobody remembered to add
// is not unchecked in a way anyone can see, it is invisible.
//
// TYPES, NOT NAMES. Reads are resolved through go/types rather than matched by
// name, for two reasons. Prose about a field is not a read of it — the comment
// above PushMFAConfig.FCMServerKey names FCMServerKey twice, and a grep counts
// that as two readers. And `Enabled` is a field on six different config structs
// here, so a name match would let one struct's live field clear another's dead
// one.
//
// TESTS ARE NOT READERS. Test files are not loaded. A field only a test touches
// is a field the product does not consult, and the test is asserting the
// plumbing rather than the effect — which is how ENABLE_MFA kept a passing test
// while doing nothing.
//
// WHAT THIS DOES NOT SEE. A field read only by code that no binary reaches
// counts as read here; that is tools/deadservice's question, and it answers it
// with a call graph. A field read into a variable that is then ignored counts as
// read too. This census answers the narrowest and least arguable form: nothing
// in the product so much as mentions it.
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
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// defaultPatterns is the whole module, and it has to be: the declaring half of
// this census is three files, but the READING half is every binary and every
// package. Loading only the config packages would find no readers at all and
// report every field — a gate that fails everything is as useless as one that
// fails nothing, and this one would have looked plausible while doing it.
var defaultPatterns = []string{"./..."}

// field is one operator-settable configuration field.
type field struct {
	Key    string // "config.PushMFAConfig.FCMServerKey" — the register key
	Tag    string // the mapstructure name, what an operator writes
	Full   string // the dotted viper key: "push_mfa.fcm_server_key"
	Struct string // the declaring struct's name
	Pkg    string // the declaring package's import path
	// Decl is the field object's declaration position, and the identity the
	// analysis compares on: the type checker records it in Defs where the field
	// is declared and in Uses at every read, across packages.
	Decl     token.Pos
	Pos      token.Position // the same position, resolved, for printing
	Settable []string       // the operator-facing surfaces that offer it
}

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 on a field nothing reads")
	census := flag.Bool("census", false, "print every settable field and whether anything reads it")
	flag.Parse()

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = defaultPatterns
	}

	declared, read, err := analyze(patterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deadconfig: %v\n", err)
		os.Exit(2)
	}
	if len(declared) == 0 {
		// A census that found nothing to census has not proved the tree is
		// clean, it has proved it did not load. Every other gate here has been
		// wrong this way at least once.
		fmt.Fprintf(os.Stderr, "deadconfig: no mapstructure-tagged fields found in %v; the load found nothing to check\n", patterns)
		os.Exit(2)
	}

	findings := report(declared, read)

	if *census {
		printCensus(declared, read)
		return
	}

	byKey := make(map[string]field, len(findings))
	for _, f := range findings {
		byKey[f.Key] = f
	}

	var unregistered []field
	for _, f := range findings {
		if _, ok := knownUnread[f.Key]; !ok {
			unregistered = append(unregistered, f)
		}
	}
	var stale []string
	for key := range knownUnread {
		if _, ok := byKey[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	fmt.Printf("deadconfig: %d settable fields, %d read, %d unread (%d registered)\n",
		len(declared), len(declared)-len(findings), len(findings), len(knownUnread))

	for _, f := range unregistered {
		fmt.Printf("\nNEW  %s\n", f.Key)
		fmt.Printf("     %s\n", f.Pos)
		fmt.Printf("     an operator sets %q and nothing in the product reads it\n", f.Full)
		for _, s := range f.Settable {
			fmt.Printf("     offered by: %s\n", s)
		}
	}
	for _, key := range stale {
		fmt.Printf("\nSTALE %s — registered as unread, and something reads it now. Delete its line in tools/deadconfig/known.go.\n", key)
	}

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0) {
		os.Exit(1)
	}
}

// analyze loads the packages and returns every mapstructure-tagged field
// together with the set of field objects the code reads, keyed by declaration
// position — which is unique across the shared FileSet and identical between the
// Defs entry that declares a field and the Uses entries that read it.
func analyze(patterns []string) (declared []field, read map[token.Pos]bool, err error) {
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
		return nil, nil, fmt.Errorf("load: %w", err)
	}
	var loadErr error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			// A package that failed to type-check yields no Uses, so every one
			// of its fields would be reported unread. Refuse rather than lie.
			//
			// The one exception is a package whose files are all behind a build
			// tag (test/integration): it contributes no readers because it
			// contains no compiled code in this configuration, and it is tests
			// besides, which are not readers here by design.
			if strings.Contains(e.Msg, "build constraints exclude all Go files") {
				continue
			}
			if loadErr == nil {
				loadErr = fmt.Errorf("%s: %v", p.PkgPath, e)
			}
		}
	})
	if loadErr != nil {
		return nil, nil, loadErr
	}

	read = map[token.Pos]bool{}
	seen := map[token.Pos]bool{}

	// Uses covers both halves of a read: `cfg.Field` records Field in the using
	// package's Uses, and so does the key of a composite literal
	// `Config{Field: v}`. Defs holds the declarations, which are not reads.
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, obj := range p.TypesInfo.Uses {
			if v, ok := obj.(*types.Var); ok && v.IsField() {
				read[v.Pos()] = true
			}
		}
	})

	// nested records, for each config struct reached as another struct's field,
	// the parent and the tag it sits under, so a field's dotted viper key can be
	// rebuilt: PushMFAConfig is Config's `push_mfa`, so FCMServerKey's key is
	// push_mfa.fcm_server_key. That dotted form is what an operator writes and
	// what the SetDefault and environment-variable tables use, so reporting the
	// leaf alone ("enabled") names a setting six structs share.
	type parent struct{ struct_, tag string }
	nested := map[string]parent{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			// Belt and braces: Tests:false already excludes _test.go, and a
			// census that silently started counting tests as readers would go
			// quiet rather than red.
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
				for _, f := range st.Fields.List {
					tag := mapstructureTag(f.Tag)
					if tag == "" {
						continue
					}
					if child := namedStruct(p.TypesInfo.TypeOf(f.Type)); child != "" {
						nested[qualify(p.PkgPath, child)] = parent{qualify(p.PkgPath, ts.Name.Name), tag}
					}
					for _, name := range f.Names {
						obj, ok := p.TypesInfo.Defs[name].(*types.Var)
						if !ok || seen[obj.Pos()] {
							continue
						}
						seen[obj.Pos()] = true
						declared = append(declared, field{
							Key:    shortPkg(p.PkgPath) + "." + ts.Name.Name + "." + name.Name,
							Tag:    tag,
							Struct: qualify(p.PkgPath, ts.Name.Name),
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

	for i, f := range declared {
		prefix := ""
		for at, hops := f.Struct, 0; hops < 16; hops++ {
			up, ok := nested[at]
			if !ok {
				break
			}
			prefix = up.tag + "." + prefix
			at = up.struct_
		}
		declared[i].Full = prefix + f.Tag
	}

	sort.Slice(declared, func(i, j int) bool { return declared[i].Key < declared[j].Key })
	return declared, read, nil
}

// namedStruct returns the name of a named struct type, or "" for anything else.
// Pointers and slices of config structs are unwrapped; a map or a primitive is
// not a nesting level.
func namedStruct(t types.Type) string {
	switch v := t.(type) {
	case *types.Pointer:
		return namedStruct(v.Elem())
	case *types.Slice:
		return namedStruct(v.Elem())
	case *types.Named:
		if _, ok := v.Underlying().(*types.Struct); ok {
			return v.Obj().Name()
		}
	}
	return ""
}

func qualify(pkgPath, name string) string { return pkgPath + "." + name }

// report returns the declared fields nothing reads, each carrying the
// operator-facing surfaces that offer it — which is what makes an unread field a
// defect rather than tidying: a field no one can set is dead code, a field the
// docs and the shipped config offer is a promise the product does not keep.
func report(declared []field, read map[token.Pos]bool) []field {
	var findings []field
	for _, f := range declared {
		if read[f.Decl] {
			continue
		}
		f.Settable = settableSurfaces(f)
		findings = append(findings, f)
	}
	return findings
}

func mapstructureTag(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	unquoted := strings.Trim(tag.Value, "`")
	name := reflect.StructTag(unquoted).Get("mapstructure")
	if name == "" || name == "-" {
		return ""
	}
	// `mapstructure:"foo,squash"` binds under foo; the options are not the name.
	if i := strings.Index(name, ","); i >= 0 {
		name = name[:i]
	}
	return name
}

func shortPkg(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// settableSurfaces names where an operator meets the field: a viper default, the
// environment-variable map, or a line in a shipped config file. Textual on
// purpose — these are the surfaces a human reads, and a key that appears in one
// of them has been offered whether or not viper ever loads that file.
//
// Matched on the full dotted key, never the leaf: `enabled` is a field on six
// config structs here, and reporting `sms.enabled`'s default as evidence for
// push_mfa.enabled is the kind of confident wrong answer that gets a gate
// switched off.
func settableSurfaces(f field) []string {
	var out []string
	for _, src := range []string{
		"internal/common/config/config.go",
		"internal/gateway/config.go",
		"internal/sms/service.go",
	} {
		body, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, `"`+f.Full+`"`) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.Contains(trimmed, "SetDefault("):
				out = append(out, fmt.Sprintf("%s:%d a viper default: %s", src, i+1, trimmed))
			case strings.Contains(trimmed, "BindEnv(") || strings.HasSuffix(trimmed, ","):
				out = append(out, fmt.Sprintf("%s:%d an environment variable: %s", src, i+1, trimmed))
			}
		}
	}
	// A shipped config file nests, so the line carries the leaf under its
	// parent's block. Tracking the enclosing top-level block is what separates
	// push_mfa's `enabled:` from sms's, tls's and adaptive_mfa's.
	files, _ := filepath.Glob("configs/*.yaml")
	for _, name := range files {
		body, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		want := ""
		if i := strings.Index(f.Full, "."); i >= 0 {
			want = f.Full[:i]
		}
		block := ""
		for i, line := range strings.Split(string(body), "\n") {
			if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
				block = strings.TrimSuffix(strings.TrimSpace(line), ":")
			}
			if !strings.HasPrefix(strings.TrimSpace(line), f.Tag+":") {
				continue
			}
			if want != "" && block != want {
				continue
			}
			if want == "" && strings.HasPrefix(line, " ") {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d a shipped config file: %s", name, i+1, strings.TrimSpace(line)))
		}
	}
	return out
}

func printCensus(declared []field, read map[token.Pos]bool) {
	for _, f := range declared {
		status := "read"
		if !read[f.Decl] {
			status = "UNREAD"
		}
		fmt.Printf("%-6s %-70s %s\n", status, f.Key, f.Full)
	}
}
