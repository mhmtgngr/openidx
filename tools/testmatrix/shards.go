package main

// Sharded matrix entries: one package's tests split across several jobs.
//
// internal/access ran as a single ~18-minute job (858 s of tests, almost all
// of it sequential container-backed DB tests), the longest leg of the unit
// matrix. It is now several entries with the same `paths:` and a `run:` regex
// each, passed to `go test -run`. That trades one hand-written list for
// another, and a hand-written list cannot notice what is missing from it: a
// test whose name no shard's regex matches would compile, appear in the
// package, and never run anywhere but the Race Detector.
//
// So the shards are checked against the tree, not trusted. For every group of
// entries sharing one `paths:` value, each top-level Test/Example/Fuzz function
// in those directories must match EXACTLY ONE of the group's regexes: none is a
// test no job runs, two is a test run twice and a sign the partition is not
// what its author thought. Benchmarks are not selected by -run and are left
// out. The regexes are compiled with Go's regexp package, the engine
// `go test -run` uses, so this check and the test binary cannot disagree.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type matrixEntry struct {
	pkg   string
	paths string
	run   string
}

// matrixEntries reads the test-unit matrix's include list. It reads only the
// matrix block -- a step's `run:` must never be taken for an entry's -- and it
// is strict in the same way matrixPrefixes is: an entry it cannot read is an
// error, never a silent skip.
func matrixEntries(path string) ([]matrixEntry, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the workflow: %w", err)
	}
	text := string(src)
	start := strings.Index(text, "\n  test-unit:\n")
	if start < 0 {
		return nil, fmt.Errorf("%s has no test-unit job", path)
	}
	job := text[start+1:]
	inc := regexp.MustCompile(`(?m)^ +include:\s*$`).FindStringIndex(job)
	if inc == nil {
		return nil, fmt.Errorf("the test-unit job in %s has no matrix include list", path)
	}
	block := job[inc[1]:]
	// The include list ends at the first line indented no deeper than the
	// job's own keys (four spaces): services:, steps:, ...
	if end := regexp.MustCompile(`(?m)^ {0,4}\S`).FindStringIndex(block); end != nil {
		block = block[:end[0]]
	}

	itemRE := regexp.MustCompile(`(?m)^\s+- package:\s*(.+)$`)
	locs := itemRE.FindAllStringSubmatchIndex(block, -1)
	if len(locs) == 0 {
		return nil, fmt.Errorf("the test-unit include list in %s has no `- package:` entries", path)
	}
	keyRE := func(key string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^\s+` + key + `:\s*(.+)$`)
	}
	pathsRE, runRE := keyRE("paths"), keyRE("run")

	var out []matrixEntry
	for i, loc := range locs {
		end := len(block)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		item := block[loc[0]:end]
		e := matrixEntry{pkg: unquote(block[loc[2]:loc[3]])}
		if m := pathsRE.FindStringSubmatch(item); m != nil {
			e.paths = strings.Join(strings.Fields(unquote(m[1])), " ")
		}
		if m := runRE.FindStringSubmatch(item); m != nil {
			e.run = unquote(m[1])
		}
		out = append(out, e)
	}
	return out, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 && !strings.HasPrefix(s, "'") && !strings.HasPrefix(s, `"`) {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) >= 2 && (s[0] == '\'' && s[len(s)-1] == '\'' || s[0] == '"' && s[len(s)-1] == '"') {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, "''", "'")
	}
	return s
}

// topLevelTestsRE finds the functions `go test -run` selects from. A test
// function is declared at column 0 in gofmt'd code, which ci.yml's lint
// enforces.
var topLevelTestsRE = regexp.MustCompile(`(?m)^func ((?:Test|Example|Fuzz)\w*)\(`)

// testsUnder lists the top-level test functions in the directories a `paths:`
// value names (`./x/...` includes everything beneath x), keyed "dir.Name".
func testsUnder(root, paths string) ([]string, error) {
	var out []string
	for _, spec := range strings.Fields(paths) {
		recursive := strings.HasSuffix(spec, "/...")
		dir := filepath.Join(root, strings.TrimPrefix(strings.TrimSuffix(spec, "/..."), "./"))
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if p != dir && (!recursive || skipDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") || info.Name() == "testdata") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			for _, m := range topLevelTestsRE.FindAllStringSubmatch(string(src), -1) {
				out = append(out, filepath.ToSlash(rel)+"."+m[1])
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("list the tests under %s: %w", spec, err)
		}
	}
	sort.Strings(out)
	return out, nil
}

// shardFindings checks every group of sharded entries. It returns the number of
// tests it checked and one finding per test matched by zero or several shards,
// plus a finding for a group that mixes sharded and unsharded entries.
func shardFindings(root string, entries []matrixEntry) (checked int, findings []string, err error) {
	groups := map[string][]matrixEntry{}
	var order []string
	for _, e := range entries {
		if _, ok := groups[e.paths]; !ok {
			order = append(order, e.paths)
		}
		groups[e.paths] = append(groups[e.paths], e)
	}
	for _, paths := range order {
		g := groups[paths]
		sharded := 0
		for _, e := range g {
			if e.run != "" {
				sharded++
			}
		}
		if sharded == 0 {
			continue
		}
		if sharded != len(g) {
			findings = append(findings, fmt.Sprintf("paths %q: %d of %d entries carry a run: regex; an entry without one runs every test again", paths, len(g)-sharded, len(g)))
			continue
		}
		res := make([]*regexp.Regexp, len(g))
		for i, e := range g {
			re, cerr := regexp.Compile(e.run)
			if cerr != nil {
				findings = append(findings, fmt.Sprintf("%s: run: %q does not compile: %v", e.pkg, e.run, cerr))
				return checked, findings, nil
			}
			res[i] = re
		}
		tests, terr := testsUnder(root, paths)
		if terr != nil {
			return checked, findings, terr
		}
		if len(tests) == 0 {
			findings = append(findings, fmt.Sprintf("paths %q: sharded, but no test functions were found under it", paths))
			continue
		}
		for _, t := range tests {
			name := t[strings.LastIndex(t, ".")+1:]
			var hits []string
			for i, re := range res {
				if re.MatchString(name) {
					hits = append(hits, g[i].pkg)
				}
			}
			checked++
			switch len(hits) {
			case 1:
			case 0:
				findings = append(findings, fmt.Sprintf("%s: no shard's run: regex matches it, so no unit job runs it", t))
			default:
				findings = append(findings, fmt.Sprintf("%s: matched by %d shards (%s); the shards must partition the tests", t, len(hits), strings.Join(hits, ", ")))
			}
		}
	}
	return checked, findings, nil
}
