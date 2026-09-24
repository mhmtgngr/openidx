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
	revokes  bool // revokes or deletes refresh tokens in the same body
}

// refreshTokenStatement is a statement that ends refresh tokens in the
// database, written out rather than through this package's helpers: the
// device revoke's by-agent revocation and the DSAR paths' deletes.
var refreshTokenStatement = regexp.MustCompile(`(?is)(UPDATE\s+oauth_refresh_tokens\s+SET\s+revoked_at\b|DELETE\s+FROM\s+oauth_refresh_tokens\b)`)

// refreshTokenRevokers are the calls that revoke refresh tokens: this
// package's two, and the per-session helper internal/identity and
// internal/oauth each keep for the path that ends one session.
var refreshTokenRevokers = map[string]bool{
	"RevokeRefreshTokens":        true,
	"RevokeUserRefreshTokens":    true,
	"revokeSessionRefreshTokens": true,
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
			severs, captures, revokes := false, false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING && severingStatement.MatchString(x.Value) {
						severs = true
					}
					if x.Kind == token.STRING && refreshTokenStatement.MatchString(x.Value) {
						revokes = true
					}
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "sessionend" && strings.HasPrefix(x.Sel.Name, "For") {
						captures = true
					}
					if refreshTokenRevokers[x.Sel.Name] {
						revokes = true
					}
				}
				return true
			})
			if severs {
				out = append(out, severingFunc{key: filepath.ToSlash(rel) + "#" + fn.Name.Name,
					line: fset.Position(fn.Pos()).Line, captures: captures, revokes: revokes})
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

// AND EVERY ONE OF THEM ENDS WHAT THE SESSION CAN STILL MINT.
//
// Marking a session row revoked, or deleting it, stops nothing a device
// notices: the refresh grant reads the refresh token's own row and the
// revoked_session marker. That was found in the Sessions page (#992), and then
// in the password change and reset, the lifecycle action, oauth-service's own
// funnel, the admin console's revoke paths, breach containment, the kill switch
// and the device revoke -- one path at a time, each by reading it. This census
// reads them all: a function that ends sessions revokes their refresh tokens in
// the same body, or it is registered below with the reason it need not.
//
// refreshTokensSurvive is the register. An entry that stops reproducing fails
// the run, so it can only shrink.
var refreshTokensSurvive = map[string]string{
	"internal/identity/session_repository.go#Terminate": "the row removal and nothing else; its one caller, Service.TerminateSession, revokes the session's refresh tokens first (revokeSessionRefreshTokens)",
	"internal/identity/service.go#deprovisionUser": "the same call disables or deletes the account, and the refresh grant refuses every token of a disabled or missing user (userIsActive); the tokens themselves survive, so an account enabled again refreshes on those no live marker covers. " +
		"Every disable path shares that, most of them without touching a session, so it is to be closed in one place rather than here",
	"internal/identity/service.go#handleOffboardUser":  "disables the account in the same transaction; see internal/identity/service.go#deprovisionUser",
	"internal/provisioning/service.go#deprovisionUser": "disables or deletes the account in the same call; see internal/identity/service.go#deprovisionUser",
}

func TestEveryPathThatEndsSessionsRevokesTheirRefreshTokens(t *testing.T) {
	root := repoRoot(t)
	found := severingFunctions(t, root)
	if len(found) < 10 {
		t.Fatalf("found only %d severing functions under internal/; this census is looking at the wrong thing", len(found))
	}

	seen := map[string]bool{}
	for _, f := range found {
		if reason, ok := refreshTokensSurvive[f.key]; ok {
			seen[f.key] = true
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is registered without a reason", f.key)
			}
			if f.revokes {
				t.Errorf("%s revokes the refresh tokens now; remove it from refreshTokensSurvive", f.key)
			}
			continue
		}
		if !f.revokes {
			t.Errorf("%s (line %d) revokes or deletes sessions rows and leaves their refresh tokens as they were.\n"+
				"The refresh grant never reads the sessions table: it decides on the refresh token's own row and "+
				"on the revoked_session marker, which lives in Redis. Call sessionend.RevokeRefreshTokens or "+
				"RevokeUserRefreshTokens on the same handle before the statement, or register the function in "+
				"refreshTokensSurvive with the reason its tokens may stay.", f.key, f.line)
		}
	}
	for key := range refreshTokensSurvive {
		if !seen[key] {
			t.Errorf("refreshTokensSurvive names %q, which no longer ends sessions; remove it", key)
		}
	}
}
