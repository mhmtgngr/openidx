package checks

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// "I could not measure this" was indistinguishable from "I measured it and it
// is mildly concerning".
//
// Seven checks dispatch on runtime.GOOS with cases for linux, darwin and
// windows, and answer anything else with StatusWarn 0.5, "…not supported on
// %s". Warns do not count against compliance, so on a build where GOOS is
// android or ios — which is exactly what gomobile produces for the companion
// app — disk_encryption (configured severity: critical), screen_lock,
// patch_level, firewall, antivirus, domain_joined and integrity all returned a
// warn without looking at the device, and the summary came out COMPLIANT.
//
// CheckResult.Unsupported is the missing distinction. These cases pin it on
// both sides: the flag is set exactly where a platform has no implementation,
// and it is set NOWHERE else — a check that genuinely examined the device and
// is unhappy must never be able to excuse itself as unmeasurable.

// TestUnsupportedIsSetOnEveryPlatformFallback derives the set of checks that
// dispatch on runtime.GOOS from the package's own source, so a check added
// later with the same shape is covered without anyone remembering to add it
// here. The register below is what a fallback must look like.
func TestUnsupportedIsSetOnEveryPlatformFallback(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	var missing []string
	var scanned int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(src)
		// The fallback is identified by the message it returns, which is the
		// same sentence in every one of them.
		if !strings.Contains(text, "not supported on %s") &&
			!strings.Contains(text, "not fully implemented on %s") {
			continue
		}
		scanned++
		if !strings.Contains(text, "Unsupported: true") {
			missing = append(missing, f)
		}
	}

	if scanned == 0 {
		t.Fatal("found no platform-fallback checks at all — this test is not reading the package")
	}
	sort.Strings(missing)
	for _, f := range missing {
		t.Errorf("%s returns a result for an operating system it has no implementation for, "+
			"without setting Unsupported. Its warn would be counted as a clean measurement, "+
			"and a device nothing examined would be reported compliant.", f)
	}
	t.Logf("%d checks carry a platform fallback; all mark it unsupported", scanned)
}

// TestUnsupportedIsNotSetOnRealResults: the flag excuses a check from the
// compliance sum, so a real measurement must never carry it. Derived from the
// AST rather than a list — every composite literal of CheckResult that sets
// Unsupported must sit in a function that also mentions runtime.GOOS.
func TestUnsupportedIsNotSetOnRealResults(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, perr := parser.ParseFile(fset, f, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", f, perr)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			var setsUnsupported bool
			var mentionsGOOS bool
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				switch v := inner.(type) {
				case *ast.KeyValueExpr:
					if id, ok := v.Key.(*ast.Ident); ok && id.Name == "Unsupported" {
						if lit, ok := v.Value.(*ast.Ident); ok && lit.Name == "true" {
							setsUnsupported = true
						}
					}
				case *ast.SelectorExpr:
					if x, ok := v.X.(*ast.Ident); ok && x.Name == "runtime" && v.Sel.Name == "GOOS" {
						mentionsGOOS = true
					}
				}
				return true
			})
			if setsUnsupported && !mentionsGOOS {
				t.Errorf("%s: %s sets Unsupported without dispatching on runtime.GOOS. "+
					"The flag removes a check from the compliance sum; only a missing "+
					"platform implementation may claim it.", f, fn.Name.Name)
			}
			return true
		})
	}
}

// unsupportedCheck stands in for a check on a platform it has no
// implementation for.
type unsupportedCheck struct{ name string }

func (c *unsupportedCheck) Name() string { return c.name }
func (c *unsupportedCheck) Run(context.Context, map[string]interface{}) *CheckResult {
	return &CheckResult{
		Status:      StatusWarn,
		Score:       0.5,
		Message:     c.name + " check not supported on testos",
		Unsupported: true,
	}
}

type passingCheck struct{ name string }

func (c *passingCheck) Name() string { return c.name }
func (c *passingCheck) Run(context.Context, map[string]interface{}) *CheckResult {
	return &CheckResult{Status: StatusPass, Score: 1}
}

// TestEngineCarriesUnsupportedThrough: the flag has to survive the engine, or
// the summary that reads it never sees one.
func TestEngineCarriesUnsupportedThrough(t *testing.T) {
	reg := NewRegistry()
	reg.Register("disk_encryption", &unsupportedCheck{name: "disk_encryption"})
	reg.Register("agent_version", &passingCheck{name: "agent_version"})

	results := NewEngine(reg).RunChecks(context.Background(), []CheckConfig{
		{Type: "disk_encryption", Severity: "critical"},
		{Type: "agent_version", Severity: "low"},
	})

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	byType := map[string]*CheckResult{}
	for _, r := range results {
		byType[r.CheckType] = r.Result
	}
	if !byType["disk_encryption"].Unsupported {
		t.Error("the engine dropped Unsupported; a check that could not run would be " +
			"counted as a measurement")
	}
	if byType["agent_version"].Unsupported {
		t.Error("a passing check came back marked unsupported")
	}
}

// TestUnsupportedSerialisesOnlyWhenSet keeps the wire format unchanged for
// every existing reporter: the field is omitempty, so a desktop report looks
// exactly as it did before.
func TestUnsupportedSerialisesOnlyWhenSet(t *testing.T) {
	quiet := &CheckResult{Status: StatusPass, Score: 1}
	loud := &CheckResult{Status: StatusWarn, Score: 0.5, Unsupported: true}

	if got := mustJSON(t, quiet); strings.Contains(got, "unsupported") {
		t.Errorf("a supported result serialises the flag: %s", got)
	}
	if got := mustJSON(t, loud); !strings.Contains(got, `"unsupported":true`) {
		t.Errorf("an unsupported result does not serialise the flag: %s", got)
	}
}

func mustJSON(t *testing.T, r *CheckResult) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
