package sessionend

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// EVERY PATH THAT ENDS A SESSION OUTSIDE oauth-service CAPTURES IT FIRST.
//
// The seam only works if every severing path uses it; a new "revoke this
// user's sessions" in a new file that forgets the capture is a session whose
// relying parties are never told, and nothing at runtime would notice -- the
// sever succeeds, the drainer has nothing to drain, and the relying party
// keeps its session open, which is the defect this package exists to remove.
//
// So this census reads the tree: every function under internal/ whose body
// carries a statement that revokes or deletes sessions rows must, in the
// same body, call one of this package's captures. The funnel in
// internal/oauth is the one exemption, by name: it announces directly, with
// the key, and is what the capture exists to reach.
//
// It reads FUNCTION BODIES, not files, for the reason the ticker census gives:
// a 7000-line service file holds many unrelated statements, and what the
// answer is about is the function that ends the session.

var severingStatement = regexp.MustCompile(`(?is)(DELETE\s+FROM\s+sessions\b|UPDATE\s+sessions\s+SET\s+revoked\b)`)

// exemptFunctions may end sessions without the capture, each with its reason.
var exemptFunctions = map[string]string{
	"internal/oauth/session_policy.go#revokeSessionWithRedis": "the funnel itself: it holds the key and announces directly through notifyBackchannelLogout",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test's working directory")
		}
		dir = parent
	}
}

type severingFunc struct {
	key      string // rel/path.go#FuncName
	line     int
	captures bool
}

// severingFunctions finds every function under internal/ (tests excluded)
// whose body holds a severing statement, and whether the body calls a
// capture from this package.
func severingFunctions(t *testing.T, root string) []severingFunc {
	t.Helper()
	var out []severingFunc
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !severingStatement.Match(src) {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			severs, captures := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING && severingStatement.MatchString(x.Value) {
						severs = true
					}
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "sessionend" && strings.HasPrefix(x.Sel.Name, "For") {
						captures = true
					}
				}
				return true
			})
			if severs {
				out = append(out, severingFunc{key: filepath.ToSlash(rel) + "#" + fn.Name.Name, line: fset.Position(fn.Pos()).Line, captures: captures})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func TestEveryPathThatEndsSessionsCapturesThemForBackChannelLogout(t *testing.T) {
	root := repoRoot(t)
	found := severingFunctions(t, root)

	// Vacuity: the tree is known to hold the funnel and more than a dozen
	// severing paths; finding fewer means the census is reading the wrong
	// thing, not that the tree is clean.
	if len(found) < 10 {
		t.Fatalf("found only %d severing functions under internal/; this census is looking at the wrong thing", len(found))
	}

	seenExempt := map[string]bool{}
	for _, f := range found {
		if reason, ok := exemptFunctions[f.key]; ok {
			seenExempt[f.key] = true
			if reason == "" {
				t.Errorf("%s is exempt without a reason", f.key)
			}
			continue
		}
		if !f.captures {
			t.Errorf("%s (line %d) revokes or deletes sessions rows without calling sessionend.ForUser / ForSession / ForSessions first.\n"+
				"Only oauth-service can tell a relying party that a session ended (it holds the signing key). "+
				"Every other path captures the session into backchannel_logout_pending BEFORE its own statement, "+
				"because the row it needs is what the statement removes. Add the capture on the same handle, "+
				"or register the function in exemptFunctions with the reason it may stay silent.", f.key, f.line)
		}
	}
	for key := range exemptFunctions {
		if !seenExempt[key] {
			t.Errorf("exemption %q names a function that no longer ends sessions; remove it", key)
		}
	}
}
