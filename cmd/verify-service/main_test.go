package main

import (
	"os/exec"
	"strings"
	"testing"
)

// forbidden are the packages that would make this binary a database client.
// pgx is the driver itself; internal/common/database is the package that
// reaches it, and naming it too makes the failure message point at the import
// somebody actually wrote rather than at a transitive dependency six hops down.
var forbidden = []string{
	"github.com/jackc/pgx",
	"github.com/openidx/openidx/internal/common/database",
}

// TestVerifyServiceLinksNoDatabaseDriver is the reason this binary exists.
//
// The claim of the verification tier is not that it happens not to open a
// connection today -- it is that it CANNOT, so an operator can give it a
// NetworkPolicy with no egress to PostgreSQL, run it at a replica count the
// database could never support, and keep it serving through a database outage.
// A claim like that is worth exactly as much as the thing that enforces it, and
// nothing in a build, a vet or a unit test notices the day somebody imports a
// package that happens to drag a driver along. That is not hypothetical: it is
// how internal/common/middleware came to put pgx in every service that
// validated a bearer, and how cmd/gateway-service links a PostgreSQL driver
// today for no reason but the Redis constructor sharing a package with the
// Postgres one.
//
// It reads the graph with `go list` rather than golang.org/x/tools/go/packages,
// and that is not a style choice: tools/racecost's census fails any test binary
// that links the loader without gating on -race, because loading and
// type-checking the whole module costs 8-13 GB under the race detector and
// kills the runner with no failing test to read. `go list -deps` answers the
// only question here -- what does this binary reach -- for the price of a
// subprocess, so there is nothing to gate.
func TestVerifyServiceLinksNoDatabaseDriver(t *testing.T) {
	// Each line is one package in the transitive closure, followed by its own
	// imports, which is what lets a failure name the hop that pulled the driver
	// in rather than just the driver.
	cmd := exec.Command("go", "list", "-deps", "-f", `{{.ImportPath}} {{join .Imports " "}}`, ".")
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 50 {
		// A `go list` that resolved almost nothing would pass this test
		// vacuously, which is the one outcome a guard must never produce.
		t.Fatalf("go list returned %d package(s); the import graph did not load", len(lines))
	}

	reached := make(map[string]bool, len(lines))
	importedBy := make(map[string]string, len(lines))
	for _, line := range lines {
		path, imports, _ := strings.Cut(line, " ")
		reached[path] = true
		for _, imp := range strings.Fields(imports) {
			if _, seen := importedBy[imp]; !seen {
				importedBy[imp] = path
			}
		}
	}

	for path := range reached {
		for _, bad := range forbidden {
			if path != bad && !strings.HasPrefix(path, bad+"/") {
				continue
			}
			via := importedBy[path]
			if via == "" {
				via = "this package"
			}
			t.Errorf("cmd/verify-service reaches %q (imported by %q).\n"+
				"The verification tier is defined by having no database: it holds no pool, "+
				"is deployed without egress to PostgreSQL, and must keep serving keys through "+
				"a database outage. If the new code genuinely needs what that package offers, "+
				"split the part it needs into a leaf package the way "+
				"internal/common/jwksverify was split out of internal/common/middleware.",
				path, via)
		}
	}
}
