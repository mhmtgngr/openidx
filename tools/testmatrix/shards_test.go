package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shardTree writes a workflow with the given include list and a package
// internal/p holding the given test functions, and returns the root.
func shardTree(t *testing.T, include string, funcs ...string) string {
	t.Helper()
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "jobs:\n  test-unit:\n    strategy:\n      matrix:\n        include:\n" + include +
		"    steps:\n      - run: go test -run 'NotAnEntry' ${{ matrix.paths }}\n"
	if err := os.WriteFile(filepath.Join(wf, "ci.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(root, "internal", "p")
	if err := os.MkdirAll(filepath.Join(pkg, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	src.WriteString("package p\n\n")
	for _, f := range funcs {
		src.WriteString("func " + f + "(t *testing.T) {}\n")
	}
	if err := os.WriteFile(filepath.Join(pkg, "p_test.go"), []byte(src.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// A subpackage is covered by ./internal/p/... and must be partitioned too.
	if err := os.WriteFile(filepath.Join(pkg, "sub", "s_test.go"), []byte("package sub\n\nfunc TestZed(t *testing.T) {}\nfunc BenchmarkIgnored(b *testing.B) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func runShards(t *testing.T, root string) (int, []string) {
	t.Helper()
	entries, err := matrixEntries(filepath.Join(root, workflowPath))
	if err != nil {
		t.Fatalf("matrixEntries: %v", err)
	}
	n, f, err := shardFindings(root, entries)
	if err != nil {
		t.Fatalf("shardFindings: %v", err)
	}
	return n, f
}

const twoShards = `          - package: p (1/2)
            paths: ./internal/p/...
            run: '^Test[A-M]'
          - package: p (2/2)
            paths: ./internal/p/...
            run: '^Test([N-Z]|[^A-Z]|$)|^Example|^Fuzz'
          - package: other
            paths: ./internal/other/...
`

func TestShardsThatPartitionTheTestsPass(t *testing.T) {
	root := shardTree(t, twoShards, "TestAlpha", "TestNorth", "Test_underscore", "ExampleThing", "FuzzParse")
	n, f := runShards(t, root)
	if len(f) != 0 {
		t.Fatalf("a partition was reported: %v", f)
	}
	if n != 6 {
		t.Errorf("checked %d tests, want 6 (five in p, one in p/sub; the benchmark is not selected by -run)", n)
	}
}

func TestATestNoShardMatchesIsAFinding(t *testing.T) {
	include := strings.Replace(twoShards, `'^Test([N-Z]|[^A-Z]|$)|^Example|^Fuzz'`, `'^Test[N-Z]'`, 1)
	root := shardTree(t, include, "TestAlpha", "Test_underscore")
	_, f := runShards(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "Test_underscore") || !strings.Contains(f[0], "no shard") {
		t.Fatalf("findings = %v, want exactly one naming Test_underscore as unmatched", f)
	}
}

func TestATestTwoShardsMatchIsAFinding(t *testing.T) {
	include := strings.Replace(twoShards, `'^Test[A-M]'`, `'^Test[A-N]'`, 1)
	root := shardTree(t, include, "TestNorth")
	_, f := runShards(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "TestNorth") || !strings.Contains(f[0], "2 shards") {
		t.Fatalf("findings = %v, want exactly one naming TestNorth as matched twice", f)
	}
}

func TestAnUnshardedEntryBesideShardsIsAFinding(t *testing.T) {
	include := twoShards + "          - package: p again\n            paths: ./internal/p/...\n"
	root := shardTree(t, include, "TestAlpha")
	_, f := runShards(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "without one runs every test again") {
		t.Fatalf("findings = %v, want the mixed group reported", f)
	}
}

// A step's `run:` must never be read as a matrix entry's.
func TestAStepRunIsNotAnEntry(t *testing.T) {
	root := shardTree(t, twoShards, "TestAlpha")
	entries, err := matrixEntries(filepath.Join(root, workflowPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %+v, want the three include items", entries)
	}
	for _, e := range entries {
		if strings.Contains(e.run, "NotAnEntry") {
			t.Fatalf("the step's run: leaked into entry %+v", e)
		}
	}
	if entries[1].run != `^Test([N-Z]|[^A-Z]|$)|^Example|^Fuzz` {
		t.Errorf("run = %q; the single quotes must be stripped and the regex kept verbatim", entries[1].run)
	}
}

// The real workflow: its shards must partition the real tree. This is the same
// check the testmatrix job runs, kept here so `go test ./tools/...` sees it.
func TestTheRepositorysShardsPartitionItsTests(t *testing.T) {
	n, f := runShards(t, "../..")
	if len(f) != 0 {
		t.Fatalf("ci.yml's sharded entries do not partition their tests:\n  %s", strings.Join(f, "\n  "))
	}
	if n == 0 {
		t.Log("no sharded entries in ci.yml")
	}
}
