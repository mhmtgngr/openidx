package oauth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/revocation"
)

// A REVOCATION HAS TO OUTLIVE WHAT IT REVOKES.
//
// There are two revocation mechanisms in this package and they answer the
// question "how long must this record live" differently.
//
//   - The PER-TOKEN blacklist gets it right. MarkAccessTokenRevoked derives its
//     Redis TTL from the token's own expiry: `ttl := time.Until(expiresAt)`.
//     Once the token would have died on its own, the entry is garbage.
//   - The PER-USER marker -- the one /oauth/logout-all, an access review, a
//     leaver's deprovisioning and the kill switch all write -- uses a constant,
//     revocation.MarkerTTL, seven days. Its comment justifies that as
//     "comfortably longer than any access token this product mints (an hour by
//     default)".
//
// AN HOUR IS THE DEFAULT, NOT THE LIMIT. access_token_lifetime is a per-client
// INTEGER column, set through client registration, and nothing caps it. A
// client configured with thirty days mints thirty-day tokens; the marker
// revoking them expires after seven. IsAccessTokenRevoked reads a missing
// marker as "not revoked" -- correctly, since it cannot distinguish never-
// revoked from expired -- so on day eight the revoked token is accepted again.
//
// Revocation that un-revokes itself is worse than no revocation, because an
// operator watched it succeed.
//
// The invariant is one sentence: NO PATH MINTS AN ACCESS TOKEN THAT OUTLIVES
// THE MARKER ABLE TO REVOKE IT. These tests are that sentence.

func TestNoClientCanBeGivenATokenLifetimeTheMarkerCannotOutlive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime int
		want     int
	}{
		{"the default is untouched", 3600, 3600},
		{"a week is exactly the limit", int(revocation.MarkerTTL.Seconds()), int(revocation.MarkerTTL.Seconds())},
		{"thirty days is clamped", 30 * 24 * 3600, int(revocation.MarkerTTL.Seconds())},
		{"zero means the default", 0, 3600},
		{"negative is not a lifetime", -1, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &OAuthClient{AccessTokenLifetime: tc.lifetime}
			if got := c.EffectiveAccessTokenLifetime(); got != tc.want {
				t.Errorf("EffectiveAccessTokenLifetime() = %d, want %d", got, tc.want)
			}
			if time.Duration(c.EffectiveAccessTokenLifetime())*time.Second > revocation.MarkerTTL {
				t.Errorf("a token of %ds outlives the %s marker that revokes it",
					c.EffectiveAccessTokenLifetime(), revocation.MarkerTTL)
			}
		})
	}
}

// THE CENSUS, because a clamp only helps at the call sites that use it, and
// there are seven. A new grant type added next year is one `client.
// AccessTokenLifetime` away from minting a token nothing can revoke, and it
// would look exactly like the code beside it.
//
// AST rather than grep: the field name appears in this file's own comments and
// in the struct definition, and a guard that cannot tell a field access from a
// sentence is a guard people write around.
func TestNoMintingPathReadsTheRawClientLifetime(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// Vacuity: a moved package would make every assertion below pass.
	if len(files) < 10 {
		t.Fatalf("only %d files in this package; this guard is looking at the wrong tree", len(files))
	}

	var findings []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, perr := parser.ParseFile(fset, f, nil, 0) // 0: comments discarded
		if perr != nil {
			t.Fatalf("parse %s: %v", f, perr)
		}
		// The store reads and writes the column -- that is how the value gets
		// in and out of the database -- and the clamp itself has to read the
		// raw field or it would have nothing to clamp. Everything else that
		// touches this field is minting something from it.
		if f == "oauth_client_store.go" {
			continue
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name.Name == "EffectiveAccessTokenLifetime" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "AccessTokenLifetime" {
					return true
				}
				pos := fset.Position(sel.Pos())
				findings = append(findings, fmt.Sprintf("%s:%d (in %s)", f, pos.Line, fn.Name.Name))
				return true
			})
		}
	}

	if len(findings) > 0 {
		t.Errorf("%d place(s) read client.AccessTokenLifetime directly instead of EffectiveAccessTokenLifetime(): %v\n"+
			"A token minted from the raw column can outlive revocation.MarkerTTL, and the per-user marker that "+
			"revokes it -- written by /oauth/logout-all, an access review, a leaver's deprovisioning and the kill "+
			"switch -- expires first. IsAccessTokenRevoked then reads a missing marker as 'not revoked', because it "+
			"cannot tell never-revoked from expired, and the token starts working again.",
			len(findings), findings)
	}
}

// The relationship the constant depends on, asserted where it is used rather
// than in a comment that cannot fail.
func TestTheMarkerOutlivesTheLongestTokenTheProductWillMint(t *testing.T) {
	longest := time.Duration(maxAccessTokenLifetimeSeconds) * time.Second
	if longest > revocation.MarkerTTL {
		t.Fatalf("the longest mintable access token is %s and the revocation marker lives %s: "+
			"a token revoked on day one is accepted again once its marker expires", longest, revocation.MarkerTTL)
	}
}

// REFUSED AT REGISTRATION, not just clamped at mint. Clamping keeps an already
// configured client safe; refusing is how the person configuring a NEW one
// finds out, instead of setting thirty days, being handed seven, and believing
// the first number.
func TestAClientCannotBeRegisteredWithALifetimeTheMarkerCannotOutlive(t *testing.T) {
	tooLong := maxAccessTokenLifetimeSeconds + 1
	if err := validateAccessTokenLifetime(&OAuthClient{AccessTokenLifetime: tooLong}); err == nil {
		t.Errorf("a client asking for %ds was accepted; the revocation marker lives %s, so a token that "+
			"long is accepted again the moment its marker expires", tooLong, revocation.MarkerTTL)
	}
	for _, ok := range []int{0, 3600, maxAccessTokenLifetimeSeconds} {
		if err := validateAccessTokenLifetime(&OAuthClient{AccessTokenLifetime: ok}); err != nil {
			t.Errorf("a client asking for %ds was refused: %v", ok, err)
		}
	}
}

// And both write paths have to ask. A refusal wired into Create alone would let
// an existing client be edited past the limit, which is the same defect one
// screen later.
func TestBothClientWritePathsCheckTheLifetime(t *testing.T) {
	const file = "oauth_client_store.go"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	checked := map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		if fn.Name.Name != "Create" && fn.Name.Name != "Update" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "validateAccessTokenLifetime" {
				checked[fn.Name.Name] = true
			}
			return true
		})
	}

	for _, want := range []string{"Create", "Update"} {
		if !checked[want] {
			t.Errorf("PostgresOAuthClientStore.%s does not call validateAccessTokenLifetime: a client can be "+
				"given an access token lifetime the per-user revocation marker cannot outlive", want)
		}
	}
}
