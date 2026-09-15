package repohygiene

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY BINARY THIS REPOSITORY CAN BUILD HAS TO BE IGNORED WHERE IT LANDS.
//
// `go build ./cmd/foo` writes `foo` into the WORKING DIRECTORY, not next to its
// package. So every directory under cmd/ and tools/ has a matching name at the
// repository root waiting to be committed by accident, and .gitignore carries a
// hand-written list of them.
//
// A hand-written list drifts, and this one did: cmd/event-relay was added and
// the list was not, so a 42.8 MB binary went in with the commit that added the
// binary's source. It was caught in the same minute; the next one would not be.
// Eight of the sixteen cmd/ entries and fifteen of the seventeen tools/ entries
// were missing at the same time -- the list had been drifting for a while,
// silently, because nothing compared it to the tree.
//
// This is that comparison. It is not a style rule: it fails when a real,
// multi-megabyte build artifact has become committable.
func TestEveryBuildableBinaryIsIgnored(t *testing.T) {
	const root = "../.."

	ignored := ignoredRootPaths(t, filepath.Join(root, ".gitignore"))

	var missing []string
	var checked int
	for _, parent := range []string{"cmd", "tools"} {
		for _, name := range subdirs(t, filepath.Join(root, parent)) {
			dir := filepath.Join(root, parent, name)
			// Only `package main` produces a binary. A helper package with
			// nothing but tests (this one) builds to nothing, and demanding an
			// ignore line for it would be noise the next reader has to dismiss.
			if !isMainPackage(t, dir) {
				continue
			}
			checked++
			if !ignored[name] {
				missing = append(missing, parent+"/"+name+" -> /"+name)
			}
		}
	}

	// Vacuity: a moved or empty tree would make the loop above pass over
	// nothing, which is the failure mode of every list-checking test.
	if checked < 25 {
		t.Fatalf("only %d directories found under cmd/ and tools/; this guard is looking at the wrong tree", checked)
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d buildable binary name(s) are not in .gitignore:\n  %s\n\n"+
			"`go build ./<dir>` drops the binary in the working directory, so each of these is a "+
			"multi-megabyte file one `git add -A` away from the history. Add a `/<name>` line for each.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// AND THE RULE ONLY WORKS ON FILES GIT IS NOT ALREADY TRACKING.
//
// .gitignore does not untrack anything. A binary committed BEFORE its ignore
// line stays tracked forever while the line sits there looking like it is doing
// something -- which is exactly what happened to `/orgscope`: the entry existed
// and a 7.08 MB build of it was in the tree regardless, from before the entry.
// So the ignore list is necessary and not sufficient, and this checks the other
// half.
//
// It asks GIT what is tracked rather than guessing from what is on disk. A
// developer's own `go build` leaves a binary at the root and the ignore line
// keeps it out of a commit; that is the system working, not a finding. The
// question is only ever "is this committed", and git is the one that knows.
func TestNoBuiltBinaryIsTrackedAtTheRepositoryRoot(t *testing.T) {
	const root = "../.."

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH; this guard asks git what is tracked")
	}

	buildable := map[string]bool{}
	for _, parent := range []string{"cmd", "tools"} {
		for _, name := range subdirs(t, filepath.Join(root, parent)) {
			if isMainPackage(t, filepath.Join(root, parent, name)) {
				buildable[name] = true
			}
		}
	}
	if len(buildable) < 20 {
		t.Fatalf("only %d buildable commands found; this guard is looking at the wrong tree", len(buildable))
	}

	var tracked []string
	for name := range buildable {
		cmd := exec.Command("git", "ls-files", "--error-unmatch", "--", name)
		cmd.Dir = root
		if err := cmd.Run(); err == nil {
			tracked = append(tracked, name)
		}
	}
	if len(tracked) > 0 {
		sort.Strings(tracked)
		t.Errorf("%d build artifact(s) are TRACKED at the repository root: %s\n"+
			"An ignore line does not untrack a file that was committed before it. Remove them with "+
			"`git rm --cached <name>`; the entry in .gitignore then does what it always looked like it was doing.",
			len(tracked), strings.Join(tracked, ", "))
	}
}

func ignoredRootPaths(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "/") || strings.HasSuffix(line, "/") {
			continue
		}
		out[strings.TrimPrefix(line, "/")] = true
	}
	if len(out) < 5 {
		t.Fatalf("only %d root-anchored entries parsed from %s; the parser or the file has changed", len(out), path)
	}
	return out
}

func subdirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// isELF reads the four magic bytes rather than trusting a name: the question is
// whether this is a compiled artifact, and a file called `migrate` could be
// anything.
func isELF(path string) bool {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if n, rerr := f.Read(magic[:]); rerr != nil || n != 4 {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

// isMainPackage reports whether a directory builds to a command.
func isMainPackage(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "package main" {
				return true
			}
		}
	}
	return false
}
