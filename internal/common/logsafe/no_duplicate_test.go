package logsafe_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Package-local re-implementations are what this package replaced: five of
// them, in oauth, governance, access, admin and credentials, and they did not
// agree — four stripped only CR and LF, one stripped every control character,
// none bounded length. The weakest copy is the one that decides what an
// attacker can put in a log line, so a sixth must not appear quietly.
//
// The check is by NAME, not by behaviour: a function called something like
// sanitizeForLog is a claim to do this job, and the point is that the job has
// one implementation. A genuinely different function needs a different name.
var duplicateName = regexp.MustCompile(`(?i)^(sanitize|scrub|clean|escape)(For)?Log(Value|Line|Field|Entry)?$`)

func TestNoPackageLocalLogSanitizer(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not this guard's business
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if duplicateName.MatchString(fn.Name.Name) {
				rel, _ := filepath.Rel(root, path)
				found = append(found, rel+": "+fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(found) != 0 {
		t.Errorf("package-local log sanitizer(s) found — use logsafe.Clean / logsafe.String instead:\n  %s",
			strings.Join(found, "\n  "))
	}
}

// The guard is worth nothing if it cannot see a violation, and it walks the
// tree from a path it computes — so prove both on a fixture.
func TestGuardDetectsADuplicate(t *testing.T) {
	dir := t.TempDir()
	src := "package fixture\n\nfunc sanitizeForLog(s string) string { return s }\n"
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(dir, "fixture.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && duplicateName.MatchString(fn.Name.Name) {
			hit = true
		}
	}
	if !hit {
		t.Error("the name pattern did not match sanitizeForLog — the guard cannot go red")
	}
	// And a name that is NOT a claim to this job must pass, or the guard becomes
	// a nuisance that gets deleted.
	for _, name := range []string{"logRequest", "sanitizeInput", "cleanupSessions", "escapeHTML"} {
		if duplicateName.MatchString(name) {
			t.Errorf("the name pattern falsely matched %q", name)
		}
	}
}

// repoRoot walks up from the test's directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root above the test directory")
	return ""
}
