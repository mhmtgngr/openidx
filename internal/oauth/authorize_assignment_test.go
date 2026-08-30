package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthorizeAssignmentDecision: the gate is opt-in per client so deploy one
// cannot lock an operator out of a first-party client that has no assignments.
func TestAuthorizeAssignmentDecision(t *testing.T) {
	cases := []struct {
		name       string
		requires   bool
		assigned   bool
		enforce    bool
		wantIssue  bool
		wantReport bool
	}{
		{"default row: no requirement, flag off", false, false, false, true, false},
		{"client does not require assignment", false, false, true, true, false},
		{"requires, assigned", true, true, true, true, false},
		{"requires, unassigned, report mode", true, false, false, true, true},
		{"requires, unassigned, enforced", true, false, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issue, report := authorizeAssignmentDecision(tc.requires, tc.assigned, tc.enforce)
			if issue != tc.wantIssue {
				t.Errorf("issue = %v, want %v", issue, tc.wantIssue)
			}
			if report != tc.wantReport {
				t.Errorf("report = %v, want %v", report, tc.wantReport)
			}
		})
	}
}

// TestEveryMintSiteCallsAssignmentGate is a source-shape guard, in the style of
// TestSingleAuthorizationCodeIssuancePath (authcode_issuance_test.go) and
// TestHostedLoginEnforcesMFA (hosted_mfa_test.go): it asserts every KNOWN place
// this service mints an authorization code calls assignmentGateAllows before
// it mints. It answers "is the ordering right at each site I already know
// about" — TestNoUngatedMintSite below answers the complementary question,
// "did I miss a site", by enumerating every call to CreateAuthorizationCode in
// the package rather than trusting a hand-maintained list. Both are needed:
// this test's hand-maintained `sites` list is exactly the kind of list a new
// mint site can silently fall outside of, which is why round 2 of this gate's
// review found a sixth mint site (handleCallback, the federated-SSO return
// leg) that this test's list did not cover.
//
// This is the regression guard for the Critical the first cut of this gate
// shipped with: issueAuthorizationCode was gated, but four other live mint
// sites — handleAuthorizeConsent, handleAuthorizeConsentV2,
// issueHostedAuthorizationCode (the hosted login page BrowZer/mobile/desktop
// use) and handleMagicLinkVerify — were not, so an unassigned user could still
// obtain a code through any of them with no error and no audit record, even
// with ACCESS_ASSIGNMENT_ENFORCE on. A missed call site is silent, which is
// exactly why a table test on the pure decision function alone cannot catch
// it — this must check the wiring in source.
func TestEveryMintSiteCallsAssignmentGate(t *testing.T) {
	sites := []struct {
		file     string
		funcSig  string
		mintCall string
	}{
		{"service.go", "func (s *Service) issueAuthorizationCode(", "s.CreateAuthorizationCode("},
		{"service.go", "func (s *Service) handleAuthorizeConsent(", "s.CreateAuthorizationCode("},
		{"service.go", "func (s *Service) handleAuthorizeConsentV2(", "s.authorizeHandler.IssueAuthorizationCode("},
		{"service.go", "func (s *Service) handleCallback(", "s.CreateAuthorizationCode("},
		{"hosted_mfa.go", "func (s *Service) issueHostedAuthorizationCode(", "s.CreateAuthorizationCode("},
		{"handlers_passwordless.go", "func (s *Service) handleMagicLinkVerify(", "s.CreateAuthorizationCode("},
	}

	for _, site := range sites {
		t.Run(site.funcSig, func(t *testing.T) {
			src, err := os.ReadFile(site.file)
			if err != nil {
				t.Fatalf("read %s: %v", site.file, err)
			}
			fn := string(src)
			start := strings.Index(fn, site.funcSig)
			if start < 0 {
				t.Fatalf("%q not found in %s — has it been renamed or moved?", site.funcSig, site.file)
			}
			fn = fn[start:]
			end := strings.Index(fn, "\n}\n")
			if end < 0 {
				t.Fatalf("could not delimit function starting %q in %s", site.funcSig, site.file)
			}
			fn = fn[:end]

			mintAt := strings.Index(fn, site.mintCall)
			if mintAt < 0 {
				t.Fatalf("expected %q to call %q — has the mint site moved or been renamed? If this function no longer mints a code, remove it from this guard's site list", site.funcSig, site.mintCall)
			}
			gateAt := strings.Index(fn, "s.assignmentGateAllows(")
			if gateAt < 0 {
				t.Fatalf("%q must call s.assignmentGateAllows before minting a code — this is the enforcement point for applications with no published route", site.funcSig)
			}
			if gateAt > mintAt {
				t.Errorf("%q calls %q before the assignment gate — the gate must run first so a refusal can pre-empt the mint", site.funcSig, site.mintCall)
			}
		})
	}
}

// mintSiteDisposition records, for every function in this package that calls
// CreateAuthorizationCode, why that is safe:
//
//   - "gated": the function itself calls s.assignmentGateAllows before the
//     mint — TestEveryMintSiteCallsAssignmentGate above asserts the ordering
//     for each of these by name.
//   - anything else: a specific reason the mint site is deliberately exempt
//     from calling the gate itself.
//
// TestNoUngatedMintSite below enumerates every real call site by parsing this
// package's source (not by trusting this map, or the hand-maintained list in
// TestEveryMintSiteCallsAssignmentGate, to be complete) and fails if it finds
// one that is not a key here, or if a key here no longer corresponds to a
// real call site. Extending the allowlist is exactly the point when a new
// mint site is added: the failure forces a person to decide, in the same
// commit, whether it needs the gate — rather than a seventh mint site
// surviving three review rounds the way the sixth (handleCallback) survived
// two.
var mintSiteDisposition = map[string]string{
	"issueAuthorizationCode":       "gated",
	"handleAuthorizeConsent":       "gated",
	"handleCallback":               "gated",
	"issueHostedAuthorizationCode": "gated",
	"handleMagicLinkVerify":        "gated",

	// AuthorizeHandler.IssueAuthorizationCode (authorize.go) takes a plain
	// context.Context, not a *gin.Context — it has no request to attach a 403
	// or an audit event to, and returns (string, error) to its caller. Its
	// only caller, handleAuthorizeConsentV2, gates before invoking it: since
	// this function's own client_id is only known from the same Redis session
	// IssueAuthorizationCode consumes as part of minting, the caller takes an
	// extra non-destructive pre-fetch of that session up front purely to learn
	// client_id for the gate. See handleAuthorizeConsentV2's comment for the
	// fail-closed-under-enforcement handling of that pre-fetch's own error case.
	"IssueAuthorizationCode": "exempt: no *gin.Context to gate with; gated by its caller handleAuthorizeConsentV2 instead",
}

// TestNoUngatedMintSite is the exhaustiveness half of the mint-site guard
// (TestEveryMintSiteCallsAssignmentGate is the ordering half — the two answer
// different questions). It parses every non-test .go file in this package,
// finds every function whose body calls CreateAuthorizationCode (by selector
// name, so it catches both s.CreateAuthorizationCode(...) and
// h.service.CreateAuthorizationCode(...)), and asserts that set is EXACTLY
// mintSiteDisposition — no unlisted function (a new, unreviewed mint site),
// and no stale entry (a listed function that no longer mints).
func TestNoUngatedMintSite(t *testing.T) {
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, path := range goFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "CreateAuthorizationCode" {
				continue // skip the definition itself
			}
			mints := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CreateAuthorizationCode" {
					mints = true
				}
				return true
			})
			if mints {
				found[fn.Name.Name] = true
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("found no function calling CreateAuthorizationCode at all — the AST walk is broken, not the codebase")
	}

	for name := range found {
		if _, ok := mintSiteDisposition[name]; !ok {
			t.Errorf("function %q calls CreateAuthorizationCode but is not in mintSiteDisposition — "+
				"decide whether it needs s.assignmentGateAllows before minting a code, then add it to the map "+
				"(as \"gated\" plus a subtest in TestEveryMintSiteCallsAssignmentGate, or with a specific exemption reason)", name)
		}
	}
	for name := range mintSiteDisposition {
		if !found[name] {
			t.Errorf("mintSiteDisposition lists %q but it no longer calls CreateAuthorizationCode — remove the stale entry", name)
		}
	}
}
