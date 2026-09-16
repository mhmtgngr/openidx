package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/cell"
)

// EVERY TOKEN THIS PACKAGE MINTS, AND WHETHER IT CARRIES THE CELL STAMP.
//
// I patched one minter and called the claim done. There are three that produce
// a bearer an API will be handed -- GenerateJWT, the SAML flow's
// generateTokensForUser, and RFC 8693's issueExchangedToken -- and stamping
// only the first would have made cell.Guard refuse SAML and token-exchange
// callers the moment an install set CELL_ID, because Misdirected reads an
// unstamped token as one that predates the claim and serves it... in the same
// cell. In the WRONG cell it would 404 from a database that does not hold the
// tenant, which is the outcome the 421 exists to replace. A guard that works
// for tokens from one flow and not another is worse than no guard: the
// behaviour depends on how the caller logged in.
//
// So the minters are derived from the source rather than listed from memory,
// and each one has to be in this register with an answer. A new mint added
// later fails here until somebody decides which kind of token it is.
//
// WHAT THIS DOES NOT MEASURE. It reads the assignment, not a signed token: the
// claim sets of GenerateJWT and generateTokensForUser are built from live
// PostgreSQL rows and no test in this package mints one end to end. The runtime
// half -- a cell claim surviving into the gin context and producing a 421 -- is
// measured in internal/common/middleware (TestTheCellTheIssuerStampedReachesThe-
// Guard). What is left unmeasured is the join between them: that the string this
// assignment writes is the same string that arrives in the claims map. That is
// a JWT round-trip through a library both sides already use, and naming it is
// cheaper than a seeded database.

// stamped: this token is presented to an API behind cell.Guard.
// unstamped: it is not, and why.
var (
	stamped = map[string]bool{
		"service.go#GenerateJWT#claims":                true,
		"service.go#generateTokensForUser#claims":      true,
		"token_exchange.go#issueExchangedToken#claims": true,
	}

	unstamped = map[string]string{
		"service.go#GenerateIDToken#claims": "An ID token is handed to the CLIENT to read, not back to an API as a bearer. " +
			"cell.Guard reads the bearer, so a stamp here would be a claim nothing consults -- and OIDC clients validate " +
			"the claim set they are given, so an unexpected one is a change to a contract we do not own.",
		"service.go#generateTokensForUser#idClaims": "The SAML flow's ID token, same reason as GenerateIDToken.",
		"ssf.go#BuildSET#claims": "A Security Event Token: this issuer SENDS it to a receiver's endpoint. It is not " +
			"presented to us and is never a bearer, and the cell that emitted an event is not something a receiver has " +
			"any use for.",
		"stepup.go#generateStepUpToken#claims": "A proof token carried ALONGSIDE the bearer, and a free function with no " +
			"Service receiver -- it has no cellID to stamp. The bearer it accompanies is stamped, and that is what the " +
			"guard reads: a step-up token in the wrong cell cannot arrive without its bearer arriving too, and the bearer " +
			"is refused first.",
		"token_exchange.go#issueExchangedToken#act": "Not a token. This is the nested `act` (actor) CLAIM VALUE inside the " +
			"exchanged token, per RFC 8693 4.1.",
	}
)

// mints derives every jwt.MapClaims literal assigned to a variable in the
// package's non-test sources, keyed file#function#variable, with whether that
// same variable is later given the cell claim.
func mints(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	out := map[string]bool{}
	for _, pkg := range pkgs {
		for path, f := range pkg.Files {
			file := filepath.Base(path)
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				// Which variables in this function are given the cell claim.
				got := map[string]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					as, ok := n.(*ast.AssignStmt)
					if !ok || len(as.Lhs) != 1 {
						return true
					}
					ix, ok := as.Lhs[0].(*ast.IndexExpr)
					if !ok {
						return true
					}
					if !isCellClaim(ix.Index) {
						return true
					}
					if id, ok := ix.X.(*ast.Ident); ok {
						got[id.Name] = true
					}
					return true
				})

				ast.Inspect(fd.Body, func(n ast.Node) bool {
					as, ok := n.(*ast.AssignStmt)
					if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
						return true
					}
					cl, ok := as.Rhs[0].(*ast.CompositeLit)
					if !ok {
						return true
					}
					se, ok := cl.Type.(*ast.SelectorExpr)
					if !ok || se.Sel.Name != "MapClaims" {
						return true
					}
					id, ok := as.Lhs[0].(*ast.Ident)
					if !ok {
						return true
					}
					out[file+"#"+fd.Name.Name+"#"+id.Name] = got[id.Name]
					return true
				})
			}
		}
	}
	if len(out) < 5 {
		t.Fatalf("derived %d claim sets; the census is reading nothing", len(out))
	}
	return out
}

// isCellClaim matches the index expression `cell.Claim`, and only that: the
// literal "cell" would work at runtime and is exactly the drift this package's
// constant exists to stop, so it is not accepted here.
func isCellClaim(e ast.Expr) bool {
	se, ok := e.(*ast.SelectorExpr)
	if !ok || se.Sel.Name != "Claim" {
		return false
	}
	id, ok := se.X.(*ast.Ident)
	return ok && id.Name == "cell"
}

func TestEveryTokenThisPackageMintsHasDecidedAboutTheCellStamp(t *testing.T) {
	// The constant is what the register is written against; if it changes name
	// or value the census above stops matching and everything looks unstamped.
	if cell.Claim != "cell" {
		t.Fatalf("cell.Claim = %q; this census matches the AST expression cell.Claim, but the plan and the "+
			"deployed tokens name the claim \"cell\"", cell.Claim)
	}

	found := mints(t)

	var keys []string
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		hasStamp := found[k]
		wantStamp, registered := stamped[k]
		why, excused := unstamped[k]

		switch {
		case !registered && !excused:
			t.Errorf("%s mints a claim set that is in neither register.\n"+
				"Decide what kind of token it is: a bearer an API is handed needs the cell stamp "+
				"(add it to `stamped` and set claims[cell.Claim]), anything else needs an entry in "+
				"`unstamped` saying why not.", k)
		case registered && excused:
			t.Errorf("%s is in BOTH registers; it cannot be both.", k)
		case registered && wantStamp && !hasStamp:
			t.Errorf("%s is registered as a bearer that carries the cell stamp, but does not set claims[cell.Claim].\n"+
				"An install that sets CELL_ID would mint unstamped tokens from this flow, and cell.Guard cannot tell "+
				"those from tokens minted before the claim existed -- so a misrouted request gets a 404 from a cell "+
				"that does not hold the tenant instead of a 421 naming the cell that does.", k)
		case excused && hasStamp:
			t.Errorf("%s now sets claims[cell.Claim], but the register still explains why it does not:\n  %s\n\n"+
				"Move it to `stamped` if that reason is stale.", k, why)
		}
	}

	for k := range stamped {
		if _, ok := found[k]; !ok {
			t.Errorf("`stamped` names %s, which no longer exists; remove or rename the entry", k)
		}
	}
	for k := range unstamped {
		if _, ok := found[k]; !ok {
			t.Errorf("`unstamped` names %s, which no longer exists; remove or rename the entry", k)
		}
	}
}
