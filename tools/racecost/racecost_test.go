package racecost_test

import (
	"os/exec"
	"strings"
	"testing"
)

// moduleRoot is where `go list` must run from: this package sits two levels
// down, and the census is about every package in the module, not this one.
const moduleRoot = "../.."

// wholeModuleAnalysis are the libraries you cannot import without loading and
// type-checking whole packages at a time. go/packages with NeedTypes|NeedSyntax
// is the entry point; ssa and rta are what deadservice builds on top of it, and
// they are listed separately so that a future tool reaching for SSA directly is
// still caught.
//
// This is not a list of OUR packages -- those are derived below. It is the set
// of upstream libraries whose presence in a test binary means that binary does
// module-scale analysis.
var wholeModuleAnalysis = []string{
	"golang.org/x/tools/go/packages",
	"golang.org/x/tools/go/ssa",
	"golang.org/x/tools/go/callgraph/rta",
}

const racecostPkg = "github.com/openidx/openidx/tools/racecost"

// TestEveryWholeModuleLoaderKnowsWhatRaceCosts derives, from the module's own
// dependency graph, every test binary that does module-scale analysis, and
// requires each one to link this package.
//
// The failure it exists to prevent has happened once and left no evidence
// behind: `go test -race ./...` runs four packages at a time, deadservice's
// analysis peaks at 13.03 GB under -race and deadconfig's at 8.04 GB, and a
// runner with 16 GB dies rather than reports. There is no FAIL line to read --
// the log says "The runner has received a shutdown signal" and "exit code 143"
// under a check named Race Detector.
//
// A written list of the two tools would have been right on the day it was
// written. `go list` is right every day: add a third analyzer and this test
// names it before CI has to.
//
// What this checks is the LINK, not the call. A package that imports racecost
// and ignores Enabled would pass here. That is the honest limit of a cheap
// check, and it is bounded by the fact that the only reason to import this
// package at all is the skip -- the failure message below says so, and there is
// nothing else in it to use.
func TestEveryWholeModuleLoaderKnowsWhatRaceCosts(t *testing.T) {
	cmd := exec.Command("go", "list", "-test", "-f", "{{.ImportPath}} {{join .Deps \" \"}}", "./...")
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		t.Fatalf("go list returned %d line(s); the census read nothing and would pass vacuously", len(lines))
	}

	var missing []string
	loaders := 0
	for _, line := range lines {
		importPath, depList, ok := strings.Cut(line, " ")
		if !ok {
			continue // a package with no dependencies; nothing to analyse with
		}
		// Only the synthesised test binaries matter: the cost is paid when the
		// test runs, and `go test -race` builds exactly these.
		if !strings.HasSuffix(importPath, ".test") {
			continue
		}
		deps := strings.Fields(depList)
		if !analysesTheWholeModule(deps) {
			continue
		}
		loaders++
		if !contains(deps, racecostPkg) {
			missing = append(missing, importPath)
		}
	}

	if loaders == 0 {
		t.Fatalf("no test binary in the module links any of %v; either the analysis gates are gone "+
			"or their import paths changed, and this census is checking nothing", wholeModuleAnalysis)
	}

	for _, pkg := range missing {
		t.Errorf("%s loads and type-checks the whole module and does not link %s.\n"+
			"Under -race that costs 8-13 GB and `go test -race ./...` runs four packages at once, "+
			"so the runner is killed and the log says \"exit code 143\" under a check named Race Detector "+
			"-- with no failing test in it. Guard the whole-module half with:\n"+
			"\tif testing.Short() || racecost.Enabled {\n"+
			"\t\tt.Skip(\"loads and type-checks the whole module\")\n"+
			"\t}\n"+
			"and give the analysis a dedicated CI job that runs it uninstrumented, "+
			"the way the deadconfig and deadservice jobs do.", pkg, racecostPkg)
	}
}

func analysesTheWholeModule(deps []string) bool {
	for _, lib := range wholeModuleAnalysis {
		if contains(deps, lib) {
			return true
		}
	}
	return false
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
