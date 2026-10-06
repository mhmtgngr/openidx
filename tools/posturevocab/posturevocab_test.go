package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/access/posturevocab"
)

// The derivation is the whole tool, so it is the thing to test. The first
// draft read `case "linux":` labels as "implements linux" — which was true of
// the code as it stood and became the exact inverse of the truth the moment a
// check was fixed to decline by naming the platform it declines on. These
// cases pin all three declining shapes the tree uses and, as importantly, that
// an unrecognised shape is an error rather than a guess.

func platformsOf(t *testing.T, body string) (map[string]bool, error) {
	t.Helper()
	src := "package p\nimport \"runtime\"\nfunc f() *CheckResult {\n" + body + "\nreturn nil\n}\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v\n%s", err, src)
	}
	fn := f.Decls[len(f.Decls)-1].(*ast.FuncDecl)
	return decliningPlatforms(fn.Body)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDecliningShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string // platforms the check declines on
	}{
		{
			// The seven original checks: three real branches, a declining default.
			name: "switch with a declining default",
			body: `switch runtime.GOOS {
			case "linux":
				return nil
			case "darwin":
				return nil
			case "windows":
				return nil
			default:
				return &CheckResult{Unsupported: true}
			}`,
			want: []string{"android", "ios"},
		},
		{
			// os_version after the fix: it names the platforms it will NOT answer for.
			name: "switch whose case declines",
			body: `switch runtime.GOOS {
			case "android", "ios":
				return &CheckResult{Unsupported: true}
			}`,
			want: []string{"android", "ios"},
		},
		{
			// process_running after the fix.
			name: "if not linux, decline",
			body: `if runtime.GOOS != "linux" {
				return &CheckResult{Unsupported: true}
			}`,
			want: []string{"android", "darwin", "ios", "windows"},
		},
		{
			name: "if equals, decline",
			body: `if runtime.GOOS == "ios" {
				return &CheckResult{Unsupported: true}
			}`,
			want: []string{"ios"},
		},
		{
			// A check that never declines covers everything, and must not be
			// mistaken for one that declines everywhere.
			name: "no declining branch at all",
			body: `return &CheckResult{Status: StatusPass}`,
			want: nil,
		},
		{
			// A GOOS switch with no declining branch says nothing about
			// coverage: every arm answers.
			name: "switch where every arm answers",
			body: `switch runtime.GOOS {
			case "linux":
				return nil
			default:
				return &CheckResult{Status: StatusPass}
			}`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := platformsOf(t, tc.body)
			if err != nil {
				t.Fatalf("decliningPlatforms: %v", err)
			}
			if tc.want == nil {
				if len(got) != 0 {
					t.Fatalf("declines on %v, want nothing", keys(got))
				}
				return
			}
			gotKeys := keys(got)
			if strings.Join(gotKeys, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("declines on %v, want %v", gotKeys, tc.want)
			}
		})
	}
}

// TestComplementOfCoversEveryShippedPlatform: the "declining default" shape
// works by subtraction, so a platform missing from shippedPlatforms would be
// silently reported as covered by every check at once.
func TestComplementOfCoversEveryShippedPlatform(t *testing.T) {
	got := complementOf(nil)
	if len(got) != len(shippedPlatforms) {
		t.Fatalf("complementOf(nil) has %d entries, want %d", len(got), len(shippedPlatforms))
	}
	for _, p := range shippedPlatforms {
		if !got[p] {
			t.Errorf("%s missing from the complement", p)
		}
	}
}

// TestTheRegisterOnlyHoldsReproducingFindings runs the real scan over the real
// tree. It is what makes the register unable to rot: an entry whose finding
// has been fixed fails here, so the register can only shrink.
func TestTheRegisterOnlyHoldsReproducingFindings(t *testing.T) {
	goChecks, err := scanGoChecks("../..")
	if err != nil {
		t.Fatalf("scan Go checks: %v", err)
	}
	if len(goChecks) == 0 {
		t.Fatal("scanned no Go checks — the tool is not reading the tree")
	}
	kotlinChecks, err := scanKotlinChecks("../..")
	if err != nil {
		t.Fatalf("scan Kotlin checks: %v", err)
	}

	found := map[string]bool{}
	for _, f := range report(goChecks, kotlinChecks) {
		found[f.key()] = true
	}
	for key, reason := range knownFindings {
		if !found[key] {
			t.Errorf("known.go registers %q, which no longer reproduces — remove it.\n    reason on file: %s",
				key, reason)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("known.go registers %q with no reason", key)
		}
	}
}

// TestEveryRegisteredCheckHasCoverageSomewhere. A check registered by the
// agent that can run on no platform at all is dead weight the fleet still
// asks for.
func TestEveryRegisteredCheckHasCoverageSomewhere(t *testing.T) {
	goChecks, err := scanGoChecks("../..")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for name, cov := range goChecks {
		if len(cov.platforms) == 0 {
			t.Errorf("%s (%s) is registered by the agent and can examine no platform at all",
				name, cov.source)
		}
	}
}

// THE SERVER'S COPY. serverReport is held against fixtures here, so each of
// its four findings is shown to fire, and against the real tree below, so the
// copy in internal/access/posturevocab is shown to match the agents.

func cov(source string, params []string, platforms ...string) coverage {
	c := coverage{platforms: map[string]bool{}, source: source}
	for _, p := range platforms {
		c.platforms[p] = true
	}
	if params != nil {
		c.params = map[string]bool{}
		for _, p := range params {
			c.params[p] = true
		}
	}
	return c
}

func TestServerReportFindsEachKindOfDrift(t *testing.T) {
	goChecks := map[string]coverage{
		"a": cov("a.go", []string{"x", "z"}, "linux", "darwin"),
		"d": cov("d.go", []string{}, "windows"),
	}
	kotlinChecks := map[string]coverage{
		"b": cov("B.kt", nil, "android"),
		"d": cov("D.kt", nil, "android"),
	}
	served := []posturevocab.AgentCheck{
		// a: windows is allowed and examined nowhere; z is read and refused;
		// y is accepted and never read. macos is the server's darwin.
		{Type: "a", Platforms: []string{"linux", "macos", "windows"}, Params: []posturevocab.Param{
			{Name: "x", Kind: posturevocab.ParamVersion}, {Name: "y", Kind: posturevocab.ParamBoolean}}},
		// c: implemented by nobody.
		{Type: "c", Platforms: []string{"linux"}},
		// d: Go on windows and Kotlin on android, and the server forgot android.
		{Type: "d", Platforms: []string{"windows"}},
		// b is missing: an agent runs it and the server does not serve it.
	}
	var got []string
	for _, f := range serverReport(goChecks, kotlinChecks, served) {
		got = append(got, f.key())
		if f.describe() == "" {
			t.Errorf("%s describes itself as nothing", f.key())
		}
	}
	want := []string{
		"not_served:b:",
		"param_drift:a:y",
		"param_drift:a:z",
		"platform_drift:a:windows",
		"platform_drift:d:android",
		"served_nowhere:c:",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings\n  got  %v\n  want %v", got, want)
	}
}

// TestTheServerVocabularyMatchesTheAgents: the copy the access service serves
// from is what the agents implement, platform for platform and param for
// param.
func TestTheServerVocabularyMatchesTheAgents(t *testing.T) {
	goChecks, err := scanGoChecks("../..")
	if err != nil {
		t.Fatalf("scan Go checks: %v", err)
	}
	kotlinChecks, err := scanKotlinChecks("../..")
	if err != nil {
		t.Fatalf("scan Kotlin checks: %v", err)
	}
	for _, f := range serverReport(goChecks, kotlinChecks, posturevocab.AgentChecks()) {
		if _, ok := knownFindings[f.key()]; !ok {
			t.Errorf("%s", f.describe())
		}
	}
}

// TestTheParamsScanReadsTheChecks: the param comparison is only as good as the
// scan, and a scan that found nothing would agree with a server that accepts
// nothing. Pin what it reads from the real checks.
func TestTheParamsScanReadsTheChecks(t *testing.T) {
	goChecks, err := scanGoChecks("../..")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for name, want := range map[string]string{
		"os_version":      "min_version",
		"agent_version":   "min_version",
		"patch_level":     "max_days",
		"process_running": "processes", // read by the parseProcessList helper
		"firewall":        "",
	} {
		c, ok := goChecks[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if got := strings.Join(sortedKeys(c.params), ","); got != want {
			t.Errorf("%s reads params %q, want %q", name, got, want)
		}
	}
}

// A file that reads params and holds two checks cannot be attributed, and the
// scan says so instead of crediting both.
func TestTheParamsScanRefusesAFileItCannotAttribute(t *testing.T) {
	dir := t.TempDir()
	src := `package checks
type A struct{}
type B struct{}
func (a *A) Run(params map[string]interface{}) { _ = params["k"] }
func (b *B) Run(params map[string]interface{}) {}
`
	if err := os.WriteFile(filepath.Join(dir, "two.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanGoParams(dir); err == nil {
		t.Fatal("a file with two checks and a params read was attributed without complaint")
	}
}
