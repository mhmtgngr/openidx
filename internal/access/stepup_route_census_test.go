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
// WHAT THIS CENSUS COULD NOT SEE, AND WHAT WAS HIDING THERE.
//
// It read one file (service.go), matched one group name (`api`), and looked at
// one path prefix (/pam/). Measured: internal/access registers 23 mutating
// routes in five OTHER files, on the group names `r`, `router` and
// `publicAgent`. Any one of those three limits was enough to hide a route;
// together they hid POST /remote-support/sessions, which opens an INTERACTIVE
// remote-control session on a named device -- the same act as
// POST /pam/apps/:id/launch, which this census requires requireFreshMFA on.
//
// It was carrying no gate at all. Its group has promoteWebSocketBearer and
// authentication and nothing else; the handler checks tenancy and shape but
// neither role nor freshness; and the device-side consent that looks like the
// second control is chosen BY THE CALLER (consent_required is a field in the
// start request, defaulting to false). Any authenticated caller in the tenant
// could take control of any enrolled device in it. It is gated now, at the same
// enforcement point as the PAM launch.
//
// A GUARD KEYED ON A SPELLING CANNOT SEE WORK THAT USES NEITHER. The file and
// the group name are gone as limits: the census reads every non-test file in
// the package and accepts any receiver. The path prefix CANNOT go, because
// nothing in the tree says which routes open privileged access -- that is the
// judgement this census exists to make somebody write down. So it stays, and it
// is named as a VOCABULARY rather than left to look like a census:
// privilegedSurfaces below is a list somebody maintains, each entry is checked
// to still match something, and a privileged surface mounted under a fourth
// prefix is still invisible. That is the residual blind spot, stated rather
// than discovered.
//
// So the tree enumerates and a person classifies. Every MUTATING route under a
// privileged surface must carry one of:
//
//	requireAdminRole()   — admin authority, which carries the freshness gate
//	                       for writes (internal/access/ziti_settings_handlers.go)
//	requireFreshMFA(...) — a privileged launch or credential reveal
//
// or appear below with a reason. A new mutating route matching neither
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

	// The remote-support surface, visible here for the first time. Session
	// START carries the step-up gate and the two legal-hold WRITES carry
	// requireAdminRole (see RegisterLegalHoldAdminRoutes for the decision);
	// these are the rest.
	"POST /remote-support/sessions/:id/end": "ends a remote-control session. Ending access is never the " +
		"thing to interrupt for a second factor -- see moderation/:id/end.",
	"POST /remote-support/sessions/:id/recording/chunk": "uploads a recording chunk for a session that was " +
		"gated at its start. Refusing it would lose the evidence of a session that is running anyway.",
	"POST /remote-support/sessions/:id/recording/finalize": "closes out that upload; see recording/chunk.",
	"POST /agent/remote-support/sessions/:id/consent": "the DEVICE answering attended-support consent, " +
		"authenticated as a device (X-Agent-ID + X-Auth-Token) on the public group. There is no human " +
		"session to step up, and this is the endpoint by which the person at the machine REFUSES -- gating " +
		"the refusal is the wrong direction entirely.",
}

// privilegedSurfaces is a VOCABULARY, not a census: the path prefixes under
// which a mutating route is presumed to open privileged access. Nothing in the
// tree derives it, and a privileged surface mounted under a prefix not listed
// here is invisible to this file. Each entry is checked below to still match at
// least one route, because a prefix that matches nothing passes forever.
var privilegedSurfaces = []string{
	"/pam/",
	"/remote-support/",
	"/agent/remote-support/",
}

var (
	// Any receiver, not just `api`: the routes this census used to miss are
	// registered on `r`, `router` and `publicAgent`. The path is left open and
	// filtered against privilegedSurfaces afterwards, so that the mirror check
	// below can tell a prefix that matches nothing from one that matches.
	reRoute      = regexp.MustCompile(`(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\.(POST|PUT|PATCH|DELETE)\("(/[^"]*)",(.*)$`)
	reMutMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

// packageRoutes returns every mutating route registered anywhere in this
// package, as "<METHOD> <path>" and the rest of the registration line.
type routeReg struct {
	key   string // "POST /remote-support/sessions"
	chain string // the rest of the registration line
	in    string // file it was registered in
	fn    string // enclosing function, for a gate passed in as a parameter
}

func packageRoutes(t *testing.T) []routeReg {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, n)
	}
	sort.Strings(files)
	if len(files) < 10 {
		t.Fatalf("found %d non-test files in this package; the census is reading the wrong directory", len(files))
	}

	var out []routeReg
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		// The enclosing function is carried along because a route registered
		// inside a Register* helper may take its gate as a parameter, and
		// whether that gate EXISTS is a fact about the helper's callers, not
		// about this line. See gatedBy.
		enclosing := ""
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(line, "func ") {
				enclosing = funcName(line)
			}
			m := reRoute.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			method, path, chain := m[1], m[2], m[3]
			if !reMutMethods[method] {
				continue
			}
			// A registration whose handler chain runs onto the next line would
			// be read with a truncated chain and could look ungated (or gated)
			// by accident. Fail loudly rather than guess -- but only for the
			// routes this census judges. Widening the scan to every path in the
			// package brought in registrations that are formatted across lines
			// and are none of this file's business (POST /api/v1/access/enroll
			// is one), and failing on those would be a census that breaks on
			// somebody else's line wrap.
			if onPrivilegedSurface(path) && !strings.Contains(chain, ")") {
				t.Fatalf("%s: route %s %s spans lines; this census reads one registration per line",
					name, method, path)
			}
			out = append(out, routeReg{key: method + " " + path, chain: chain, in: name, fn: enclosing})
		}
	}
	return out
}

// funcName pulls the identifier out of a func declaration line, receiver or no.
func funcName(line string) string {
	rest := strings.TrimPrefix(line, "func ")
	if strings.HasPrefix(rest, "(") {
		if i := strings.Index(rest, ")"); i >= 0 {
			rest = strings.TrimSpace(rest[i+1:])
		}
	}
	if i := strings.IndexAny(rest, "([{ "); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// gatedBy reports whether a route registration actually carries a gate.
//
// THE FIRST VERSION OF THIS ACCEPTED THE SPELLING `privileged...` AND WAS
// WRONG, in precisely the way this file exists to catch. A route registered as
// `r.POST(path, append(privileged, handler)...)` reads as gated whether or not
// its caller passes anything, so deleting the gate from the mount site left the
// census green -- a control reporting success while the thing it is there to
// make true is not true. The mutation that found it is the one that removes
// svc.requireFreshMFA(...) from the RegisterRemoteSupportAdminRoutes call.
//
// So a variadic gate is resolved: the parameter proves nothing, and the census
// goes and looks at every call of the enclosing function for a real gate in its
// arguments. A helper that takes the parameter and is mounted once without one
// is ungated, and says so.
func gatedBy(t *testing.T, routes []routeReg, r routeReg) bool {
	t.Helper()
	if hasLiteralGate(r.chain) {
		return true
	}
	if r.fn == "" {
		return false
	}
	// The chain names one of the enclosing function's parameters; find which,
	// then follow THAT parameter through the callers by position.
	param := paramNamedIn(t, r.fn, r.chain)
	if param == "" {
		return false
	}
	return argGatedAtEveryCall(t, r.fn, param, 0)
}

func hasLiteralGate(expr string) bool {
	return strings.Contains(expr, "requireAdminRole(") || strings.Contains(expr, "requireFreshMFA(")
}

// THE FIRST TRANSITIVE VERSION OF THIS WAS POSITIONALLY BLIND, and a mutation
// found it: it accepted ANY literal gate anywhere on a caller's line. So with
// the mount site passing requireFreshMFA(...) for stepUp and nil for admin,
// the legal-hold writes -- wired to admin -- read as gated by the freshness
// gate that went to a different parameter. A control reporting success while
// the thing it exists to make true is not true, for the fourth time in this
// tree's censuses. Resolution now follows the PARAMETER: which one the route's
// chain names, which argument position that is in each caller, and what sits
// in that position -- a literal gate, another parameter (recurse), or anything
// else (an open mount).

// funcDecls maps every top-level function in the package to its declaration
// line, so a parameter list can be read for any function a route names.
func funcDecls(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "func ") {
				out[funcName(line)] = line
			}
		}
	}
	return out
}

// paramNames reads the parameter names off a func declaration line, in order.
// "r *gin.RouterGroup, stepUp, admin gin.HandlerFunc" -> [r stepUp admin].
func paramNames(decl string) []string {
	rest := decl
	if i := strings.Index(rest, ") "); strings.HasPrefix(strings.TrimPrefix(rest, "func "), "(") && i >= 0 {
		rest = rest[i+2:] // skip the receiver
	}
	open := strings.Index(rest, "(")
	if open < 0 {
		return nil
	}
	inner := rest[open+1:]
	if close := matchParen(inner); close >= 0 {
		inner = inner[:close]
	}
	var names []string
	for _, group := range splitTopLevel(inner) {
		fields := strings.Fields(strings.TrimSpace(group))
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[0]) // "admin gin.HandlerFunc" or bare "stepUp"
	}
	return names
}

// paramNamedIn returns which parameter of fn the chain mentions, as a whole
// word, or "" if none.
func paramNamedIn(t *testing.T, fn, chain string) string {
	t.Helper()
	decl, ok := funcDecls(t)[fn]
	if !ok {
		return ""
	}
	for _, name := range paramNames(decl) {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(chain) {
			return name
		}
	}
	return ""
}

// argGatedAtEveryCall follows parameter param of fn through every call site.
func argGatedAtEveryCall(t *testing.T, fn, param string, depth int) bool {
	t.Helper()
	if depth > 3 {
		return false
	}
	decls := funcDecls(t)
	idx := -1
	for i, name := range paramNames(decls[fn]) {
		if name == param {
			idx = i
		}
	}
	if idx < 0 {
		return false
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	calls := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		enclosing := ""
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "func ") {
				enclosing = funcName(line)
				continue
			}
			at := strings.Index(line, "."+fn+"(")
			if at < 0 {
				continue
			}
			calls++
			args := splitTopLevel(argList(line[at+len(fn)+2:]))
			if idx >= len(args) {
				return false // the gate position is not even supplied
			}
			arg := strings.TrimSpace(args[idx])
			switch {
			case hasLiteralGate(arg):
			case enclosing != "" && paramNamedIn(t, enclosing, arg) == arg:
				if !argGatedAtEveryCall(t, enclosing, arg, depth+1) {
					return false
				}
			default:
				return false // nil, a stub, or anything that is not a gate
			}
		}
	}
	return calls > 0
}

// argList returns the text inside the call's parentheses, given the text that
// follows the opening paren.
func argList(afterOpen string) string {
	if close := matchParen(afterOpen); close >= 0 {
		return afterOpen[:close]
	}
	return afterOpen
}

// matchParen returns the index of the ")" that closes an already-open "(".
func matchParen(s string) int {
	depth := 0
	for i, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// splitTopLevel splits on commas that are not inside parentheses or braces.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, ch := range s {
		switch ch {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func onPrivilegedSurface(path string) bool {
	for _, prefix := range privilegedSurfaces {
		if strings.Contains(path, prefix) {
			return true
		}
	}
	return false
}

// EVERY ENTRY IN THE VOCABULARY STILL MATCHES SOMETHING. Without this, deleting
// a surface -- or misspelling one -- turns the census green by shrinking what
// it looks at, which is the failure mode this whole file is about.
func TestEveryPrivilegedSurfaceStillMatchesRoutes(t *testing.T) {
	routes := packageRoutes(t)
	for _, prefix := range privilegedSurfaces {
		hits := 0
		for _, r := range routes {
			if strings.Contains(r.key, prefix) {
				hits++
			}
		}
		if hits == 0 {
			t.Errorf("privilegedSurfaces lists %q, and no mutating route in this package is under it. "+
				"Either the surface moved -- in which case this census stopped watching it and nothing "+
				"said so -- or it is gone and the entry should be deleted.", prefix)
		}
	}
}

func TestEveryMutatingPamRouteIsClassified(t *testing.T) {
	all := packageRoutes(t)
	var routes []routeReg
	for _, r := range all {
		if onPrivilegedSurface(r.key) {
			routes = append(routes, r)
		}
	}

	if len(routes) < 20 {
		t.Fatalf("found only %d mutating routes on a privileged surface — the census is not reading the "+
			"route table", len(routes))
	}

	seen := map[string]bool{}
	var unclassified []string
	for _, r := range routes {
		// A gate counts whether it is spelled on the registration line or handed
		// in at the mount site: RegisterRemoteSupportAdminRoutes takes the
		// step-up as a parameter, because the gate is a method on Service and
		// that handler has no Service. Reading only the literal spelling would
		// have called the gated route ungated -- a census that reports a defect
		// it has just had fixed is trusted exactly as little as one that misses
		// a real one.
		gated := gatedBy(t, all, r)
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
		t.Errorf("%s mutates on a privileged surface and carries neither requireAdminRole() nor "+
			"requireFreshMFA().\n"+
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
