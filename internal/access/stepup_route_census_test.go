package access

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The census that keeps the freshness gate from being a list somebody
// maintains.
//
// Gating "the PAM launch endpoints" by naming them is precisely the artefact
// that lets the next one escape: a handler is written, mounted beside its
// neighbours, and inherits every gate except the one nobody remembered to
// extend. It is not hypothetical — writing this census is what found
// POST /pam/apps/:id/launch, which opens a brokered Windows session through
// Guacamole and which the first pass of this change had missed while gating
// its five obvious siblings.
//
// So the tree enumerates and a person classifies. Every route under /pam/ that
// MUTATES must carry one of:
//
//	requireAdminRole()   — admin authority, which carries the freshness gate
//	                       for writes (internal/access/ziti_settings_handlers.go)
//	requireFreshMFA(...) — a privileged launch or credential reveal
//
// or appear below with a reason. A new mutating /pam/ route matching neither
// fails this test until somebody decides which it is. An entry that no longer
// reproduces fails it too, so the register can only shrink — the shape
// tools/tablewriters uses, for the same reason: a checker that quietly stops
// checking is the failure mode this repository keeps finding.

// notPrivilegedLaunch are the mutating /pam/ routes that neither require admin
// authority nor open privileged access, with why.
var notPrivilegedLaunch = map[string]string{
	"POST /pam/moderation/request": "asks a human to supervise a session; grants nothing. The session it " +
		"concerns was already gated at its own launch.",
	"POST /pam/moderation/:id/end": "ends supervision. Ending access is never the thing to interrupt for a " +
		"second factor — a user who cannot end a session keeps it open.",
	"PUT /pam/entries/:id": "edits an entry the caller already holds edit rights on (pamEntryAllowed, " +
		"\"edit\"). It changes a stored record, not access to a host, and admins editing entries reach it " +
		"through requireAdminRole on the sibling routes.",
	"POST /pam/entries/:id/favorite":   "a personal bookmark.",
	"DELETE /pam/entries/:id/favorite": "removes a personal bookmark.",
	"POST /pam/entries/:id/request": "asks an admin for access. Requesting is the thing you do BECAUSE you " +
		"do not have access; the grant is gated where it is issued.",
	"POST /pam/entries/:id/checkin": "returns a checked-out credential. Refusing a check-in would leave " +
		"credentials checked out, which is worse than the write it prevents.",
	"POST /pam/brokered-sessions/:id/end": "ends a brokered session; see moderation/:id/end.",
	"POST /pam/sessions/:id/end":          "ends a PAM session; see moderation/:id/end.",
}

var (
	rePamRoute   = regexp.MustCompile(`(?m)^\s*api\.(POST|PUT|PATCH|DELETE)\("(/pam/[^"]*)",(.*)$`)
	reMutMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

func TestEveryMutatingPamRouteIsClassified(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}

	type route struct{ key, chain string }
	var routes []route
	for _, m := range rePamRoute.FindAllStringSubmatch(string(b), -1) {
		method, path, chain := m[1], m[2], m[3]
		if !reMutMethods[method] {
			continue
		}
		// A registration whose handler chain runs onto the next line would be
		// read with a truncated chain and could look ungated (or gated) by
		// accident. Fail loudly rather than guess.
		if !strings.Contains(chain, ")") {
			t.Fatalf("route %s %s spans lines; this census reads one registration per line", method, path)
		}
		routes = append(routes, route{key: method + " " + path, chain: chain})
	}

	if len(routes) < 20 {
		t.Fatalf("found only %d mutating /pam/ routes — the census is not reading the route table", len(routes))
	}

	seen := map[string]bool{}
	var unclassified []string
	for _, r := range routes {
		gated := strings.Contains(r.chain, "requireAdminRole(") || strings.Contains(r.chain, "requireFreshMFA(")
		if _, registered := notPrivilegedLaunch[r.key]; registered {
			seen[r.key] = true
			if gated {
				t.Errorf("%s is registered as not-a-privileged-launch but now carries a gate — "+
					"remove its entry from notPrivilegedLaunch in stepup_route_census_test.go", r.key)
			}
			continue
		}
		if !gated {
			unclassified = append(unclassified, r.key)
		}
	}
	sort.Strings(unclassified)

	for _, key := range unclassified {
		t.Errorf("%s mutates under /pam/ and carries neither requireAdminRole() nor requireFreshMFA().\n"+
			"    Decide which it is: a privileged launch or credential reveal takes requireFreshMFA(\"pam.<action>\");\n"+
			"    an admin operation takes requireAdminRole(); anything else needs an entry, with a reason, in\n"+
			"    notPrivilegedLaunch in this file.", key)
	}

	for key := range notPrivilegedLaunch {
		if !seen[key] {
			t.Errorf("notPrivilegedLaunch lists %q, but no such mutating route is registered any more — "+
				"remove its entry", key)
		}
	}
}

// TestTheLaunchRoutesActuallyCarryTheGate is the other half: the census above
// accepts requireAdminRole as a classification, so on its own it could be
// satisfied by an install where the launch routes were merely admin-only. The
// endpoints that hand a caller live privileged access must carry the freshness
// gate specifically.
func TestTheLaunchRoutesActuallyCarryTheGate(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	src := string(b)

	for _, want := range []struct{ path, action string }{
		{"/pam/entries/:id/connect", "pam.connect"},
		{"/pam/entries/:id/reveal", "pam.reveal"},
		{"/pam/entries/:id/break-glass", "pam.break_glass"},
		{"/pam/connect/ssh", "pam.connect_ssh"},
		{"/pam/connect/cloud", "pam.connect_cloud"},
		{"/pam/brokered-sessions", "pam.broker_session"},
		{"/pam/apps/:id/launch", "pam.app_launch"},
	} {
		needle := `"` + want.path + `", svc.requireFreshMFA("` + want.action + `")`
		if !strings.Contains(src, needle) {
			t.Errorf("POST %s does not carry requireFreshMFA(%q) as its first handler — "+
				"a privileged launch that asks nothing of the person holding the device", want.path, want.action)
		}
	}
}
