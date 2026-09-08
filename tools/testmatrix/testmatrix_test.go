package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The gate's own coverage rule, checked against synthetic inputs so a failure
// here means the rule is wrong rather than the tree.
func TestCoveredByMatrix(t *testing.T) {
	prefixes := []string{"internal/access", "internal/vault", "pkg", "cmd"}

	cases := []struct {
		pkg  string
		want bool
		why  string
	}{
		{"internal/access", true, "the prefix itself"},
		{"internal/access/handlers", true, "./internal/access/... covers what is beneath it"},
		{"cmd/oauth-service", true, "one entry covers every service main"},
		{"pkg/storage", true, "pkg/... covers its children"},
		{"internal/abac", false, "no entry names it"},
		{"internal/accesslog", false,
			"a prefix must end at a path separator: internal/access must not swallow internal/accesslog"},
		{"internal/vaultkeeper", false, "same trap, the other direction"},
	}

	for _, c := range cases {
		if got := coveredByMatrix(c.pkg, prefixes); got != c.want {
			t.Errorf("coveredByMatrix(%q) = %v, want %v -- %s", c.pkg, got, c.want, c.why)
		}
	}
}

// A workflow whose matrix shape changed must fail loudly. The failure this
// guards against is the quiet one: a parser that matches nothing, finds no
// prefixes, calls every package uncovered or -- worse, if it defaulted the
// other way -- calls every package covered.
func TestAWorkflowThisParserCannotReadIsAnError(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "ci.yml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("no test-unit job", func(t *testing.T) {
		_, err := matrixPrefixes(write("jobs:\n  lint:\n    runs-on: ubuntu-latest\n"))
		if err == nil {
			t.Fatal("a workflow with no test-unit job parsed cleanly; the gate would then check nothing and pass")
		}
	})

	t.Run("matrix with no paths", func(t *testing.T) {
		_, err := matrixPrefixes(write("jobs:\n  test-unit:\n    strategy:\n      matrix:\n        package: [internal/access]\n"))
		if err == nil {
			t.Fatal("a test-unit job with no paths: entries parsed cleanly; the gate would see an empty matrix and call every package uncovered or covered by accident")
		}
	})

	t.Run("a whole-module path", func(t *testing.T) {
		_, err := matrixPrefixes(write("jobs:\n  test-unit:\n    strategy:\n      matrix:\n        include:\n          - paths: ./...\n"))
		if err == nil {
			t.Fatal("`./...` was accepted as a prefix; it covers everything, so the gate could never report a finding again")
		}
	})
}

func TestTheParserReadsGroupedPaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ci.yml")
	body := `jobs:
  test-unit:
    strategy:
      matrix:
        include:
          - package: internal/access
            paths: ./internal/access/...
          - package: a+b
            paths: ./internal/a/... ./internal/b/...
    steps:
      - run: go test ${{ matrix.paths }}

  test-race:
    steps:
      - run: go test ./...
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := matrixPrefixes(p)
	if err != nil {
		t.Fatalf("matrixPrefixes: %v", err)
	}
	want := []string{"internal/a", "internal/access", "internal/b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("prefixes = %v, want %v -- one entry may list several directories, and the job that follows test-unit must not leak in", got, want)
	}
}

// Every register entry must cite a job that exists. An entry naming a job that
// was renamed or deleted claims coverage the repository no longer has, and it
// would keep a package out of the matrix on the strength of that claim.
func TestEveryRegisterEntryNamesARealJob(t *testing.T) {
	if len(elsewhere) == 0 {
		t.Skip("the register is empty")
	}
	names, err := workflowJobNames("../..")
	if err != nil {
		t.Fatalf("read the workflows: %v", err)
	}
	quoted := regexp.MustCompile(`"([^"]+)"`)

	for pkg, reason := range elsewhere {
		if len(reason) < 80 {
			t.Errorf("%s: the register entry is %d characters. Say which job runs these tests and why the unit matrix cannot, "+
				"in enough detail that the next person can check the claim without rerunning the analysis.", pkg, len(reason))
		}
		cited := quoted.FindAllStringSubmatch(reason, -1)
		found := false
		for _, c := range cited {
			if names[c[1]] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: the register entry names no job that exists in .github/workflows. It cites %v. "+
				"A register entry citing a job that was renamed or deleted claims coverage this repository does not have.",
				pkg, quotedList(cited))
		}
	}
}

func quotedList(m [][]string) []string {
	out := make([]string, 0, len(m))
	for _, c := range m {
		out = append(out, c[1])
	}
	return out
}

func workflowJobNames(root string) (map[string]bool, error) {
	names := map[string]bool{}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	nameRE := regexp.MustCompile(`(?m)^\s*name:\s*(.+?)\s*$`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, m := range nameRE.FindAllStringSubmatch(string(src), -1) {
			names[strings.Trim(m[1], `"'`)] = true
		}
	}
	return names, nil
}

// The real check, over the real tree and the real workflow. This is the one
// that goes red when somebody adds a package and no job runs its tests.
func TestEveryTestedPackageIsRunBySomeJob(t *testing.T) {
	root := filepath.Join("..", "..")

	prefixes, err := matrixPrefixes(filepath.Join(root, workflowPath))
	if err != nil {
		t.Fatalf("read the unit matrix: %v", err)
	}
	pkgs, err := testedPackages(root)
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	if len(pkgs) < 50 {
		t.Fatalf("found only %d packages holding tests; this module has far more, so the walk is not seeing the tree "+
			"and every assertion below would pass vacuously", len(pkgs))
	}

	for _, pkg := range pkgs {
		verdict, tag := classify(root, pkg, prefixes)
		if verdict != unrun {
			continue
		}
		if tag != "" {
			t.Errorf("%s holds tests and every one of them is behind `//go:build %s`, which no job here passes: "+
				"the package compiles to zero tests and reports success. Name it in the command of the job that "+
				"does pass the tag, then record that in the register in known.go.", pkg, tag)
			continue
		}
		t.Errorf("%s holds tests and no named job runs them: it is in neither the test-unit matrix in %s nor the "+
			"register in known.go. Only `go test -race ./...` reaches it, so a failure there arrives twenty minutes "+
			"in under a check named \"Race Detector\" -- which is how seven red production-config tests in cmd/ went "+
			"unnoticed across several pushes.", pkg, workflowPath)
	}
}

// The tag rule, on synthetic files: covering a package is not running its
// tests, and this is the distinction that let a KEK-rotation proof sit in CI
// for its whole life without executing.
func TestOnlyBehindABuildTag(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	const tagged = "//go:build integration\n\npackage p\n"
	const plain = "package p\n\nfunc x() {}\n"
	const quotes = "package p\n\n// a test asserting something about\n// //go:build integration\nfunc y() {}\n"

	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"all tagged", map[string]string{"a_test.go": tagged, "b_test.go": tagged}, "integration"},
		{"none tagged", map[string]string{"a_test.go": plain}, ""},
		{"mixed", map[string]string{"a_test.go": tagged, "b_test.go": plain}, ""},
		{"disagreeing tags", map[string]string{
			"a_test.go": tagged,
			"b_test.go": "//go:build slow\n\npackage p\n",
		}, ""},
		{"the constraint must head the file", map[string]string{"a_test.go": quotes}, ""},
		{"non-test files are not consulted", map[string]string{"main.go": tagged, "a_test.go": plain}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := onlyBehindABuildTag(write(t, c.files)); got != c.want {
				t.Errorf("onlyBehindABuildTag = %q, want %q", got, c.want)
			}
		})
	}
}

func TestATaggedOnlyPackageIsNotSatisfiedByTheMatrix(t *testing.T) {
	dir := t.TempDir()
	pkg := "cmd/example"
	if err := os.MkdirAll(filepath.Join(dir, pkg), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pkg, "x_test.go"),
		[]byte("//go:build integration\n\npackage main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	verdict, tag := classify(dir, pkg, []string{"cmd"})
	if verdict != unrun {
		t.Errorf("classify = %q, want %q: ./cmd/... covers the package but passes no tags, so it compiles no tests",
			verdict, unrun)
	}
	if tag != "integration" {
		t.Errorf("tag = %q, want \"integration\"; the finding has to say what stands in the way", tag)
	}
}

// A register entry for a package the matrix now covers is stale, and stale
// entries are how a register stops meaning anything. The register only shrinks.
func TestTheRegisterCarriesNothingTheMatrixAlreadyRuns(t *testing.T) {
	root := filepath.Join("..", "..")
	prefixes, err := matrixPrefixes(filepath.Join(root, workflowPath))
	if err != nil {
		t.Fatalf("read the unit matrix: %v", err)
	}
	for pkg := range elsewhere {
		// "Under a matrix prefix" is not the test; "the matrix actually runs
		// these tests" is. cmd/rekey sits under ./cmd/... and the matrix
		// compiles none of it, which is the whole reason it has a register
		// line — reading only the prefix here would delete the line that
		// records the one real fact about that package.
		if onlyBehindABuildTag(filepath.Join(root, pkg)) == "" && coveredByMatrix(pkg, prefixes) {
			t.Errorf("%s is in the register AND actually run by the unit matrix. Drop the register line: it now "+
				"excuses nothing, and the next reader has to work out which of the two is true.", pkg)
		}
	}
}

// A register entry for a directory that no longer holds tests is the other
// stale shape -- it survives a deletion and quietly grows the exempt set.
func TestTheRegisterCarriesNothingThatIsGone(t *testing.T) {
	root := filepath.Join("..", "..")
	pkgs, err := testedPackages(root)
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	have := map[string]bool{}
	for _, p := range pkgs {
		have[p] = true
	}
	for pkg := range elsewhere {
		if !have[pkg] {
			t.Errorf("%s is in the register but holds no test files any more. Delete the line.", pkg)
		}
	}
}
