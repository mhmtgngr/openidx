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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

// root is the directory the non-Go surfaces are read from: the shipped config
// files, the documentation, the console. The command runs from the repository
// root; the tests set it, because `go test` runs from the package directory and
// a relative path that quietly reads nothing is how a census stops censusing.
var root = "."

func at(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }

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
	failOnFindings := flag.Bool("fail", false, "exit 1 on a field nothing reads or a documented setting nothing binds")
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

	phantom, err := documentedButUnbound(declared)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deadconfig: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("deadconfig: %d documented settings, %d of them bound by nothing\n",
		documentedCount, len(phantom))
	for _, p := range phantom {
		fmt.Printf("\nDOC  %s\n", p.Name)
		fmt.Printf("     %s:%d\n", p.File, p.Line)
		fmt.Printf("     %s\n", strings.TrimSpace(p.Row))
	}

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0 || len(phantom) > 0) {
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
	for _, rel := range []string{
		"internal/common/config/config.go",
		"internal/gateway/config.go",
		"internal/sms/service.go",
	} {
		src := at(rel)
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
	files, _ := filepath.Glob(at("configs", "*.yaml"))
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

// ---------------------------------------------------------------------------
// The mirror census: a setting the documentation offers that nothing binds.
//
// The half above finds a field an operator can set that the code never reads.
// This half finds the other direction, and it is the one an operator meets
// first: a row in a settings table naming an environment variable the product
// has no binding for. They set it, nothing changes, and nothing tells them --
// the same defect, arriving through the documentation rather than the struct.
//
// The docs are the surface, so they are scanned as a surface: any table row
// whose first cell is a backticked ALL_CAPS name is a row that says "this is a
// setting you can set". The bound set is derived -- the environment-variable
// map, every os.Getenv/os.LookupEnv literal in the tree, and viper's own
// OPENIDX_<KEY> spelling of every key a mapstructure field defines.
//
// knownExternal is the one written list, and it is written because the set it
// holds genuinely is not ours: variables belonging to GitHub Actions, Docker,
// HashiCorp Vault, the Android toolchain and so on. Each carries whose it is.
// ---------------------------------------------------------------------------

// docRow is one documented setting.
type docRow struct {
	Name string
	File string
	Line int
	Row  string
}

// documentedCount is how many rows the last scan looked at, so the summary can
// say what the finding count is out of.
var documentedCount int

var settingRow = regexp.MustCompile("^\\|\\s*`([A-Z][A-Z0-9_]{2,})`\\s*\\|")

// settingsHeader is the header row of a table of settings: the column is named
// Variable, Env, Setting or Knob somewhere in this repository's docs.
var settingsHeader = regexp.MustCompile(`(?i)^\|[^|]*\b(variable|env|setting|knob)s?\b`)

// documentedButUnbound returns the documented settings nothing binds.
func documentedButUnbound(declared []field) ([]docRow, error) {
	bound, err := boundEnvNames(declared)
	if err != nil {
		return nil, err
	}
	if len(bound) == 0 {
		return nil, fmt.Errorf("no environment variables found in the tree; the scan found nothing to compare against")
	}

	var docs []string
	err = filepath.WalkDir(at("docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			docs = append(docs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk docs: %w", err)
	}
	docs = append(docs, at("README.md"))

	documentedCount = 0
	var out []docRow
	for _, path := range docs {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		inSettingsTable := false
		for i, line := range strings.Split(string(body), "\n") {
			// A settings table is one whose header says so. Without this the
			// scan reads `| `GET` | /api/v1/... |` out of an endpoint table as a
			// setting named GET -- an ALL_CAPS name in a backticked first cell is
			// the shape of both.
			if !strings.HasPrefix(strings.TrimSpace(line), "|") {
				inSettingsTable = false
				continue
			}
			if settingsHeader.MatchString(line) {
				inSettingsTable = true
				continue
			}
			if !inSettingsTable {
				continue
			}
			m := settingRow.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := m[1]
			documentedCount++
			if bound[name] || knownExternal[name] != "" {
				continue
			}
			out = append(out, docRow{Name: name, File: path, Line: i + 1, Row: line})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

var envMapEntry = regexp.MustCompile(`"[a-z0-9_.]+":\s*"([A-Z][A-Z0-9_]*)"`)
var getenvLiteral = regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("([A-Z][A-Z0-9_]*)"\)`)

// boundEnvNames is every environment variable this product actually reads.
func boundEnvNames(declared []field) (map[string]bool, error) {
	bound := map[string]bool{}

	// Viper's AutomaticEnv with the OPENIDX prefix makes OPENIDX_<KEY> a name
	// for every key a mapstructure field defines, whether or not the map below
	// gives it a second, unprefixed spelling.
	replacer := strings.NewReplacer(".", "_", "-", "_")
	for _, f := range declared {
		bound["OPENIDX_"+strings.ToUpper(replacer.Replace(f.Full))] = true
	}

	// A retired setting is bound by nothing on purpose, and a settings table
	// that still offers one is the defect retired.go exists to prevent -- so
	// retired names are deliberately NOT added here.

	// The admin console is a reader too: Vite substitutes import.meta.env.VITE_*
	// at build time, so a VITE_ name the console consults is a setting an
	// operator really can set, and derived here rather than listed.
	consoleEnv := regexp.MustCompile(`import\.meta\.env\.(VITE_[A-Z0-9_]+)`)
	if err := filepath.WalkDir(at("web", "admin-console", "src"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, m := range consoleEnv.FindAllStringSubmatch(string(body), -1) {
			bound[m[1]] = true
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk the console: %w", err)
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "web", "client", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		text := string(body)
		for _, m := range envMapEntry.FindAllStringSubmatch(text, -1) {
			bound[m[1]] = true
		}
		for _, m := range getenvLiteral.FindAllStringSubmatch(text, -1) {
			bound[m[1]] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk the tree: %w", err)
	}
	return bound, nil
}
