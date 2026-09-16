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

// mounts are the binaries that run cell.Guard behind their authentication.
var mounts = []string{
	"access-service",
	"admin-api",
	"audit-service",
	"governance-service",
	"identity-service",
	"provisioning-service",
}

// unmounted are the binaries that do not, with why. This is not an oversight:
// the one entry left may not want the guard at all.
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
	"oauth-service": "RegisterRoutes takes named auth parameters (clientMgmtAuth, flowAuth) rather than a variadic list. It is also the least clear case: this service mints tokens rather than serving tenant records, its client-management and SSF surfaces are client-authenticated, and a refresh token presented to the wrong cell is a row that cell does not have -- so it fails on its own terms already. Decide whether the guard belongs here before adding it.",
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
