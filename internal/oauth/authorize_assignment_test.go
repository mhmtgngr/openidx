package oauth

import (
	"os"
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
// TestHostedLoginEnforcesMFA (hosted_mfa_test.go): it asserts every place this
// service mints an authorization code calls assignmentGateAllows before it
// mints.
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
