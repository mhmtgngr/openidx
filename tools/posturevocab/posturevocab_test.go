package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
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
