package cmd_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// EVERY BACKGROUND STARTER A BINARY CALLS, AND WHAT KEEPS IT FROM RUNNING ONCE
// PER REPLICA.
//
// Two censuses already exist and neither answers this. internal/common/leader's
// sweeps census classifies the coordination of every file containing
// time.NewTicker. cmd/identity-service's plane census asks whether a starter
// belongs to the plane the process is serving. What is between them is the join:
// which BINARIES call which starters, and does every one of those calls reach a
// coordination answer.
//
// THE HOLE THAT MAKES THE JOIN WORTH HAVING. The sweeps census finds work by
// looking for time.NewTicker in a file. Ten of the starters below have no
// ticker in their own file at all -- they hand the interval to
// leader.RunPeriodic, which owns the ticker and the gate together. That is
// correct, and it is exactly why the census cannot see them: the ticker moved
// into a helper. Measured, on this tree, today.
//
// So the shape this guard exists for is the same move WITHOUT the gate. Somebody
// writes runEvery(d, fn) in a util package, calls it from eight services, and
// the sweeps census sees ONE file -- the helper -- while eight sweeps run once
// per replica. Nothing in the tree would say so. Here, every starter a main.go
// calls has to resolve to one of three answers, and a new one resolves to none
// of them until its author picks.
//
// WHAT THIS DOES NOT MEASURE, and the plan says the same. Whether these
// starters WOULD BE BETTER OFF in their own cmd/<svc>-worker binaries is a
// question about load -- how much of a request-serving pod's CPU and pool
// budget the sweeps take, and whether separating them improves either. That
// needs a staging cell under load and cannot be answered here. The
// CLASSIFICATION is measurable and is what this file does; the benefit of
// splitting is not, and is not claimed.

// leaderGated resolves to a definition whose file hands the work to
// leader.RunPeriodic or IsLeaderForTick: one replica per interval,
// cluster-wide, with the ticker inside the gate.
const leaderGated = "leader-gated"

// tickerInOwnFile resolves to a definition whose file creates its own ticker,
// which is what the sweeps census reads. Its coordination answer lives there,
// and this census only requires that it be findable there.
const tickerInOwnFile = "ticker-in-own-file"

// notPeriodic is the written register, and the only hand-maintained part. An
// entry here is a claim that the starter does not do repeating work at all.
var notPeriodic = map[string]string{
	"StartHTTPServer": "cmd/profiler's pprof listener. It serves a port until the context ends; there is no interval " +
		"to multiply and nothing for a second replica to duplicate -- two profilers are two endpoints, not two sweeps.",
}

var starterCall = regexp.MustCompile(`\b(Start[A-Z][A-Za-z0-9_]*)\s*\(`)

// binaryStarters derives, per starter name, the binaries whose main.go calls
// it. Derived rather than listed: a list cannot see the call nobody added.
func binaryStarters(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir cmd/: %v", err)
	}
	out := map[string][]string{}
	mains := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(e.Name(), "main.go"))
		if rerr != nil {
			continue
		}
		mains++
		seen := map[string]bool{}
		for _, m := range starterCall.FindAllStringSubmatch(string(body), -1) {
			if seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			out[m[1]] = append(out[m[1]], e.Name())
		}
	}
	if mains < 10 {
		t.Fatalf("found %d main.go under cmd/; the census is reading nothing", mains)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

var starterDecl = regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?(Start[A-Z][A-Za-z0-9_]*)\(`)

var (
	declOnce  sync.Once
	declFiles map[string]string
	declErr   error
)

// declarations walks internal/ ONCE and returns starter name to declaring file.
// Once, because the first version walked the tree per starter and the package
// spent eight seconds doing the same read twenty-six times.
func declarations(t *testing.T) map[string]string {
	t.Helper()
	declOnce.Do(func() {
		declFiles = map[string]string{}
		declErr = filepath.WalkDir("../internal", func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, m := range starterDecl.FindAllStringSubmatch(string(body), -1) {
				if _, seen := declFiles[m[1]]; !seen {
					declFiles[m[1]] = filepath.ToSlash(path)
				}
			}
			return nil
		})
	})
	if declErr != nil {
		t.Fatalf("walk internal/: %v", declErr)
	}
	return declFiles
}

// defineFile finds the file under internal/ that declares a starter.
func defineFile(t *testing.T, name string) string {
	t.Helper()
	return declarations(t)[name]
}

// classify answers how a starter's repeating work is coordinated, or "" when
// nothing in its file says.
func classify(t *testing.T, file string) string {
	t.Helper()
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	src := string(body)
	switch {
	case strings.Contains(src, "leader.RunPeriodic"), strings.Contains(src, "IsLeaderForTick"):
		return leaderGated
	case strings.Contains(src, "time.NewTicker"):
		return tickerInOwnFile
	}
	return ""
}

func TestEveryBackgroundStarterReachesACoordinationAnswer(t *testing.T) {
	starters := binaryStarters(t)
	if len(starters) < 15 {
		t.Fatalf("derived %d starters; the census is reading nothing", len(starters))
	}

	names := make([]string, 0, len(starters))
	for n := range starters {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		why, registered := notPeriodic[name]

		file := defineFile(t, name)
		if file == "" {
			if registered {
				continue // a starter that lives outside internal/ and is registered.
			}
			t.Errorf("%s is called by %v but declares nowhere under internal/; the census cannot classify what it "+
				"cannot find", name, starters[name])
			continue
		}

		how := classify(t, file)
		if registered {
			if how != "" {
				t.Errorf("%s is in `notPeriodic` (%q) but %s is %s.\nIt does repeating work after all -- "+
					"remove the entry, and let the coordination answer in that file stand for it.", name, why, file, how)
			}
			continue
		}
		if how == "" {
			t.Errorf("%s (%s), started by %v, reaches no coordination answer.\n"+
				"Its file neither hands the interval to leader.RunPeriodic/IsLeaderForTick nor creates a ticker the "+
				"sweeps census can classify. If it repeats work, it runs once per replica and the operator's interval "+
				"is multiplied by a number nobody chose. Gate it, give it a ticker the census reads, or add it to "+
				"`notPeriodic` with the reason it does not repeat.", name, file, starters[name])
		}
	}
}

// The counts are a measurement, so they are pinned. A starter that quietly
// stops being leader-gated moves between these two numbers, and the diff says
// which one -- which a pass/fail alone would not.
func TestTheCoordinationSplitIsWhereItWasMeasured(t *testing.T) {
	starters := binaryStarters(t)

	counts := map[string]int{}
	for name := range starters {
		if _, ok := notPeriodic[name]; ok {
			counts["not-periodic"]++
			continue
		}
		if file := defineFile(t, name); file != "" {
			counts[classify(t, file)]++
		}
	}

	// Measured 2026-09-16 on this tree: 14 leader-gated, 11 with a ticker in
	// their own file, 1 not periodic.
	//
	// The 14 is not the 10 a first pass by hand produced, and the difference is
	// worth keeping: several files hold BOTH a ticker and the gate, and reading
	// the gate first is what classify does. A number carried over from a manual
	// count would have pinned this four too low and read as green while four
	// sweeps lost their gate.
	//
	// leader-gated is the figure that must not fall: every entry in it is a
	// sweep that would otherwise run once per replica, and access-service
	// autoscales to eight.
	const measuredLeaderGated = 14
	if counts[leaderGated] < measuredLeaderGated {
		t.Errorf("leader-gated starters dropped to %d from the %d measured; a sweep stopped being gated and now "+
			"runs in every replica", counts[leaderGated], measuredLeaderGated)
	}
	if counts[""] != 0 {
		t.Errorf("%d starter(s) reach no coordination answer; the test above names them", counts[""])
	}
	t.Logf("coordination split: leader-gated=%d ticker-in-own-file=%d not-periodic=%d",
		counts[leaderGated], counts[tickerInOwnFile], counts["not-periodic"])
}
