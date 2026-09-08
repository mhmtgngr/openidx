// Command testmatrix checks that every package in this module holding tests is
// actually run by a named CI job.
//
// WHAT WENT WRONG. .github/workflows/ci.yml runs unit tests through a matrix,
// one job per package, and that matrix was a hand-written list. It listed
// internal/* and pkg/. It did not list cmd/ -- so the ten service main packages,
// including the seven *_ProductionConfigValidation tests that are each service's
// only automated proof that it accepts a correct production start and refuses a
// weak one, had no job. When AUDIT_CHAIN_SECRET became a required production
// setting, all seven went red and stayed red across several pushes. Nothing on
// the pull request said so.
//
// They were not unverified: test-race runs `go test -race ./...` and covers the
// whole module. But it arrives twenty minutes in, under a check named "Race
// Detector", and a red tick with that name reads as a concurrency problem, not
// as "your config gate is broken in seven services". A signal that arrives late
// under the wrong name is most of the way to no signal.
//
// The deeper shape is the one this branch has met repeatedly: a hand-maintained
// allow-list cannot notice what is missing from it. tools/orgscope had it (a
// table nobody listed was invisible to the lint), and the fix there was to
// derive the census from the migration registry instead of writing it down.
// Here the equivalent is cheap: the tree knows which directories hold _test.go
// files, so compare that against what the workflow says it runs.
//
// WHAT THIS REPORTS. One finding per package that holds tests and appears in
// neither the matrix nor the register in known.go. Nothing else -- not coverage,
// not test quality, not packages without tests. A package with no tests is a
// different problem and belongs to a different gate; flagging it here would make
// this one noisy, and a gate that reports noise is a gate somebody turns off.
//
// Usage:
//
//	go run ./tools/testmatrix            # report
//	go run ./tools/testmatrix -fail      # report and exit 1 on any finding
//	go run ./tools/testmatrix -census    # every tested package and who runs it
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	var (
		failOnFindings = flag.Bool("fail", false, "exit non-zero if any tested package is run by no job")
		census         = flag.Bool("census", false, "list every tested package and what runs it")
		root           = flag.String("root", ".", "module root")
	)
	flag.Parse()

	prefixes, err := matrixPrefixes(filepath.Join(*root, workflowPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testmatrix: %v\n", err)
		os.Exit(2)
	}

	pkgs, err := testedPackages(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "testmatrix: %v\n", err)
		os.Exit(2)
	}

	var findings []string
	if *census {
		fmt.Printf("%d packages hold tests; the unit matrix runs %d path prefixes\n\n", len(pkgs), len(prefixes))
	}
	for _, pkg := range pkgs {
		verdict, tag := classify(*root, pkg, prefixes)
		if !*census {
			if verdict == unrun {
				findings = append(findings, describe(pkg, tag))
			}
			continue
		}
		switch verdict {
		case byMatrix:
			fmt.Printf("  matrix    %s\n", pkg)
		case byRegister:
			fmt.Printf("  register  %s -- %s\n", pkg, elsewhere[pkg])
		default:
			findings = append(findings, describe(pkg, tag))
			fmt.Printf("  NOBODY    %s\n", pkg)
		}
	}

	if len(findings) == 0 {
		fmt.Printf("testmatrix: all %d packages holding tests are run by a named job\n", len(pkgs))
		return
	}

	fmt.Printf("\ntestmatrix: %d package(s) hold tests that no named job runs:\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  %s\n", f)
	}
	fmt.Print(`
Each of these compiles and its tests pass or fail in silence: only
` + "`go test -race ./...`" + ` in the Race Detector job touches them, so a failure
arrives late under a name that describes something else.

Fix it in one of two ways, never by ignoring it:

  - add the package to the test-unit matrix in ` + workflowPath + `, as a
    ` + "`package`" + `/` + "`paths`" + ` pair (an existing entry's ` + "`paths`" + ` may list several
    directories, so a small package need not cost a whole runner); or
  - if some other job already runs its tests, record that in the register in
    tools/testmatrix/known.go naming the job -- the register's own test
    requires the job name to exist in .github/workflows.
`)
	if *failOnFindings {
		os.Exit(1)
	}
}

const workflowPath = ".github/workflows/ci.yml"

// matrixPrefixes reads the test-unit matrix out of the CI workflow and returns
// the directory prefixes it runs.
//
// This is a deliberately strict parser rather than a tolerant one. It has one
// job -- to know what CI actually runs -- and the failure that matters is the
// silent one: a workflow edit that changes the matrix's shape, a parser that
// quietly matches nothing, and a gate that passes because it found no packages
// to check. So every step that could come up empty is an error instead.
func matrixPrefixes(path string) ([]string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the workflow: %w", err)
	}
	text := string(src)

	start := strings.Index(text, "\n  test-unit:\n")
	if start < 0 {
		return nil, fmt.Errorf("%s has no test-unit job; if the unit tests moved, this gate must move with them", path)
	}
	rest := text[start+1:]
	// The job ends at the next top-level key (two spaces, a name, a colon).
	if end := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:$`).FindStringIndex(rest[1:]); end != nil {
		rest = rest[:end[0]+1]
	}

	pathsRE := regexp.MustCompile(`(?m)^\s+paths:\s+(\S.*)$`)
	matches := pathsRE.FindAllStringSubmatch(rest, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("the test-unit job in %s declares no `paths:` entries; the matrix shape changed and this parser no longer sees what CI runs", path)
	}

	var prefixes []string
	for _, m := range matches {
		for _, spec := range strings.Fields(strings.TrimSpace(m[1])) {
			p := strings.TrimSuffix(spec, "/...")
			p = strings.TrimPrefix(p, "./")
			p = strings.TrimSuffix(p, "/")
			if p == "" || p == "." {
				return nil, fmt.Errorf("the test-unit matrix runs %q, which covers the whole module; this gate cannot tell what has a job and what does not", spec)
			}
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	return prefixes, nil
}

// The three states a package holding tests can be in.
const (
	byMatrix   = "matrix"
	byRegister = "register"
	unrun      = "unrun"
)

// classify decides who runs a package's tests, and returns the build tag when
// that is what stands in the way.
//
// The tag rule is the second half of this gate, and it exists because covering
// a package is not the same as running its tests. cmd/rekey sits under the
// matrix's ./cmd/... entry, and its one test file begins `//go:build
// integration`, so every job that does not pass -tags compiles zero tests out
// of it and reports success — a green tick for an empty package. So a package
// whose test files are ALL behind a constraint is never satisfied by the unit
// matrix, which passes no tags: it has to be in the register, naming the job
// that does pass one.
//
// A package with a mix of tagged and untagged files (test/integration is the
// only one) still counts as matrix-covered on the untagged half, and its tagged
// half is that job's business.
func classify(root, pkg string, prefixes []string) (verdict, tag string) {
	tag = onlyBehindABuildTag(filepath.Join(root, pkg))
	if tag == "" && coveredByMatrix(pkg, prefixes) {
		return byMatrix, ""
	}
	if elsewhere[pkg] != "" {
		return byRegister, tag
	}
	return unrun, tag
}

func describe(pkg, tag string) string {
	if tag == "" {
		return pkg
	}
	return fmt.Sprintf("%s (every test file is behind `//go:build %s`, which no job here passes)", pkg, tag)
}

// onlyBehindABuildTag returns the constraint when EVERY _test.go file in dir
// carries one, and "" otherwise (including when the constraints disagree —
// that is a package to look at by hand, not one to summarise in a word).
func onlyBehindABuildTag(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	constraint := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return ""
		}
		m := buildConstraintRE.FindSubmatch(src)
		if m == nil {
			return ""
		}
		got := strings.TrimSpace(string(m[1]))
		if constraint != "" && constraint != got {
			return ""
		}
		constraint = got
	}
	return constraint
}

// Only a constraint in the file's header counts: `(?m)^//go:build` would also
// match the same text quoted inside a test that asserts something about build
// tags. Anchoring to the start of the file is what the Go toolchain does too.
var buildConstraintRE = regexp.MustCompile(`\A(?://.*\n|\s*\n)*?//go:build ([^\n]+)\n`)

// coveredByMatrix reports whether pkg falls under one of the matrix prefixes.
// `./internal/access/...` covers internal/access and everything beneath it.
func coveredByMatrix(pkg string, prefixes []string) bool {
	for _, p := range prefixes {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return false
}

// skipDirs are trees that are not part of this Go module. agent/ and the mobile
// engine carry their own go.mod and their own workflows; web/ and client/ are
// not Go at all.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "third_party": true,
	"web": true, "client": true, "agent": true, "docs": true, "site": true,
}

// testedPackages returns every directory under root that holds a _test.go file,
// as a module-relative slash path.
//
// Walking the tree rather than shelling out to `go list` is deliberate: this
// runs as a lint, and a directory whose package does not currently compile must
// still be reported. `go list` would drop it, and "the tests do not build" is
// the one state where "no job runs them" matters most.
func testedPackages(root string) ([]string, error) {
	seen := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// The root's own name is whatever the caller spelled -- "." from
			// the command line, ".." from a test two directories down -- and
			// both begin with a dot. Deciding on the name alone skipped the
			// root and walked nothing, which is a gate that reports success
			// because it looked at no files. Resolve to a module-relative path
			// first and let the root through by that.
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			if skipDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		seen[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk the tree: %w", err)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
