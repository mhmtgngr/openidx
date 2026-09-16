// Package cmd_test holds censuses that read across every binary.
package cmd_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Which binaries refuse a token minted in another cell.
//
// cell.Guard existing is worth nothing on its own: a guard nothing mounts is
// the shape this branch keeps finding, one step before it reaches production.
// So the mount is measured, and the services that do NOT have it are named with
// the reason rather than left to be discovered by whoever eventually deploys a
// second cell and wonders why one service answers 421 and another a confident
// 404 for the same misrouted request.
//
// The register only shrinks. A service that starts mounting the guard has to
// move out of `unmounted`, and one that stops mounting it fails here.
//
// THIS CENSUS'S OWN BLIND SPOT, AND WHAT CLOSING IT COST.
//
// The first version of this file named seven binaries. cmd/ holds seventeen.
// The other ten were not exempt and were not deferred -- they were invisible,
// which is a strictly worse state than either, because nothing here would ever
// have mentioned them. A binary added tomorrow that serves tenant records
// behind authentication would have joined them silently, and the census would
// have gone on reporting a complete-looking answer about a set it had chosen
// for itself. A list can be a VOCABULARY or a CENSUS; this one read as a census
// and behaved as a vocabulary.
//
// So the universe is now the tree: every directory under cmd/ with a main.go
// must appear in exactly one register, and one that appears in none fails.
// Closing it found no defect -- all ten are legitimately out of scope, and
// their reasons are below. That is the honest result, and it is worth the same
// as a defect would have been: the next one will not be invisible.
//
// The second blind spot is NOT closed here, because it cannot be closed from
// cmd/: "mounts cell.Guard" is read off the text of main.go, and mounting the
// guard says nothing about whether the authentication in front of it binds the
// claim the guard reads. That is exactly how identity-service nearly shipped a
// guard that would have served every misdirected request. It is measured in
// internal/common/middleware/cell_credential_census_test.go, against real
// tokens and a real JWKS endpoint, per credential kind -- and it found that two
// of the five ways a caller can authenticate here cannot be refused at all.

// mounts are the binaries that run cell.Guard behind their authentication.
var mounts = []string{
	"access-service",
	"admin-api",
	"audit-service",
	"governance-service",
	"identity-service",
	"provisioning-service",
}

// unmounted are the request-serving binaries that do not, with why. This is not
// an oversight: an entry here may not want the guard at all.
//
// identity-service used to be the second entry, and its reason was wrong in a
// way worth keeping: it said mounting the guard meant changing
// RegisterRoutesForProfile's signature, and that the signature was the cost. It
// was the cheap half. Service already carried cfg and logger, so the signature
// took a variadic parameter and nothing else; what actually stood in the way was
// that identity's authentication middleware bound roles by hand and never bound
// the cell claim, so a guard mounted there would have read an unset key and
// served every misdirected request. A backlog entry that names the wrong
// obstacle is a measurement nobody has taken.
var unmounted = map[string]string{
	"oauth-service":   "RegisterRoutes takes named auth parameters (clientMgmtAuth, flowAuth) rather than a variadic list. It is also the least clear case: this service mints tokens rather than serving tenant records, its client-management and SSF surfaces are client-authenticated, and a refresh token presented to the wrong cell is a row that cell does not have -- so it fails on its own terms already. Decide whether the guard belongs here before adding it.",
	"gateway-service": "It does not authenticate. The gateway mounts admission, rate limiting, security headers and OrgSlugHeader and then proxies; no middleware in cmd/gateway-service verifies a token, so there is no verified cell claim for a guard to read and one mounted here would refuse nothing. In the cell model this is also the wrong layer by design: the edge is where the tenant directory lookup belongs (see internal/common/cell's own doc), and getting the ROUTING right at the edge is a different job from making a wrong routing LEGIBLE at the destination.",
	"verify-service":  "It serves one endpoint, /.well-known/jwks.json, and it serves it to anyone -- there is no caller identity on this path at all, let alone a cell claim. A key set is also not tenant data: the question the guard answers, 'does this cell hold this tenant', does not arise. Per-cell signing keys would change that, and they are an infrastructure item (per-cell KMS) that has not been done.",
	"event-relay":     "Its HTTP server is /health and /metrics. The work is a database poller, not a request path, so nothing arrives carrying a credential. If it ever grows an authenticated endpoint this entry stops being true and has to be re-decided rather than assumed.",
	"demo-app":        "A demonstration relying party, not part of the product surface: it holds no tenant data and is not deployed alongside the services. It is listed rather than skipped so that the day it stops being a demo, somebody has to say so here.",
}

// notRequestServing are the binaries that answer no requests at all: CLIs and
// batch jobs. They are listed for one reason -- so that the registers above
// cover every binary in the tree and a new one cannot be invisible -- and the
// check below verifies the classification rather than trusting it.
var notRequestServing = map[string]string{
	"backup":          "database backup CLI",
	"migrate":         "database migration CLI",
	"openidx":         "developer CLI (this is where `openidx cell place|show` lives)",
	"openidx-connect": "end-user native-access CLI; it is an SSH client, not a server",
	"profiler":        "performance profiling CLI",
	"rekey":           "batch re-encryption job over the whole keyring",
}

func mainFor(t *testing.T, binary string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(binary, "main.go"))
	if err != nil {
		t.Fatalf("read %s/main.go: %v", binary, err)
	}
	return string(b)
}

func binaries(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(e.Name(), "main.go")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	if len(out) < 5 {
		t.Fatalf("found %d binaries under cmd/; the census is reading nothing", len(out))
	}
	return out
}

func TestTheCellGuardIsMountedWhereTheRegisterSaysItIs(t *testing.T) {
	present := map[string]bool{}
	for _, b := range binaries(t) {
		present[b] = true
	}

	for _, name := range mounts {
		if !present[name] {
			t.Errorf("mounts names cmd/%s, which does not exist; remove the entry", name)
			continue
		}
		if !strings.Contains(mainFor(t, name), "cell.Guard(") {
			t.Errorf("cmd/%s is registered as mounting cell.Guard but does not.\n"+
				"A token minted in another cell would be served here while the other services "+
				"refuse it, and the difference would be invisible. Mount it after this service's "+
				"authentication, or move the entry to `unmounted` with the reason.", name)
		}
	}

	for name, why := range unmounted {
		if !present[name] {
			t.Errorf("unmounted names cmd/%s, which does not exist; remove the entry", name)
			continue
		}
		if strings.Contains(mainFor(t, name), "cell.Guard(") {
			t.Errorf("cmd/%s now mounts cell.Guard, but the register still explains why it does not:\n  %s\n\n"+
				"Move it to `mounts` -- the backlog is shorter and the reason is stale.", name, why)
		}
	}
}

// EVERY BINARY IN THE TREE IS IN EXACTLY ONE REGISTER. This is the check that
// turns the three lists above from a vocabulary into a census: without it, the
// only binaries anybody ever looks at are the ones already written down.
func TestEveryBinaryIsClassifiedForTheCellGuard(t *testing.T) {
	inMounts := map[string]bool{}
	for _, name := range mounts {
		inMounts[name] = true
	}

	for _, name := range binaries(t) {
		var registers []string
		if inMounts[name] {
			registers = append(registers, "mounts")
		}
		if _, ok := unmounted[name]; ok {
			registers = append(registers, "unmounted")
		}
		if _, ok := notRequestServing[name]; ok {
			registers = append(registers, "notRequestServing")
		}

		switch len(registers) {
		case 1:
		case 0:
			t.Errorf("cmd/%s is in no register, so nothing in this tree has an opinion about whether a "+
				"request that reached the wrong cell should be refused there.\n"+
				"If it serves requests, put it in `mounts` (and mount the guard) or in `unmounted` WITH "+
				"THE REASON. If it answers no requests at all, put it in `notRequestServing`. Silence is "+
				"the one answer this census exists to rule out.", name)
		default:
			t.Errorf("cmd/%s is in %v. A binary is in exactly one, or the registers disagree about it and "+
				"whichever is read first wins.", name, registers)
		}
	}
}

// AND THE CLASSIFICATION IS CHECKED, not taken on trust: a binary filed as
// answering no requests must not contain a listener. Without this the cheapest
// way to satisfy the census above would be to file a new service under
// `notRequestServing` and never think about it again -- an exemption that
// writes itself is the defect shape this whole branch is about.
func TestTheNonServingBinariesReallyServeNothing(t *testing.T) {
	for name, why := range notRequestServing {
		src := mainFor(t, name)
		for _, listener := range []string{"ListenAndServe", "gin.New(", "gin.Default(", "http.Server{"} {
			if strings.Contains(src, listener) {
				t.Errorf("cmd/%s is registered as answering no requests (%q), but its main.go contains %q.\n"+
					"Either it grew a request path -- in which case it needs a decision about cell.Guard, "+
					"not an exemption inherited from when it was a CLI -- or this check is reading the "+
					"wrong file.", name, why, listener)
			}
		}
	}

	// The mirror, so the four spellings above cannot quietly stop matching
	// anything: at least one register entry has to be a real server. A guard
	// keyed on a spelling that matches nothing passes forever.
	serving := 0
	for _, name := range append(append([]string{}, mounts...), keysOf(unmounted)...) {
		if strings.Contains(mainFor(t, name), "ListenAndServe") {
			serving++
		}
	}
	if serving < len(mounts) {
		t.Errorf("only %d of the %d binaries registered as request-serving contain a listener; this check "+
			"is looking for the wrong spelling, so the exemption check above proves nothing",
			serving, len(mounts))
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
