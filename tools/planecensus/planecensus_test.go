package planecensus_test

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// moduleRoot is where `go list` must run from: this package sits two levels
// down, and the census is about every binary in the module, not this one.
const moduleRoot = "../.."

// The plane map, measured rather than asserted.
//
// WHY THIS EXISTS. A commit on this branch claimed cmd/gateway-service linked a
// PostgreSQL driver "for no reason but database.NewRedisFromConfig sharing a
// package with the Postgres half". That was written from reading one import in
// one main.go. It was wrong: the binary reaches pgx through five independent
// routes -- internal/common/middleware, internal/metrics,
// internal/common/syssettings, internal/appaccess and internal/stepup -- and
// splitting the Redis half out moved exactly one of them. The claim had already
// reached a merged pull request and the plan before anything measured it.
//
// Reading an import list is not measuring an import graph, which is the same
// mistake this branch keeps finding in the product: a conclusion drawn one
// frame too low. So the map is derived here, and a claim about which binaries
// are free of the database has to agree with `go list` or fail.
//
// WHAT IT GUARDS. dbFree names the binaries whose value depends on holding no
// database: they are deployed without egress to PostgreSQL and must keep
// serving through an outage. A binary on that list gaining a driver fails, and
// so does a list entry for a binary that no longer exists. The counts of the
// rest are not policed -- most services are supposed to reach the database, and
// a census that complained about them would be noise somebody turns off.

// dbFree are the binaries that must not reach a PostgreSQL driver.
//
// Entries are a promise about a deployment, not an aspiration: each of these
// can be given a NetworkPolicy with no egress to the database. Adding a binary
// here is a claim that must already be true -- the test tells you if it is not.
var dbFree = map[string]string{
	"verify-service": "the verification tier (ADR-2): serves /.well-known/jwks.json from an HTTP key cache, holds no pool, deployed without egress to PostgreSQL",
}

// notes records, for binaries that DO reach the driver, whether that is
// intended. It is documentation with a build failure attached: a name here that
// no longer exists is removed, so the list cannot describe a tree that is gone.
var notes = map[string]string{
	"gateway-service": "reaches pgx through middleware, metrics, syssettings, appaccess and stepup. Splitting the Redis half out of internal/common/database removed one route of five; the others are real uses (auth, pool metrics, settings, app-access and step-up all read tenant-scoped tables). Making this binary database-free is a much larger job than one import, and it is not obviously worth doing -- it is recorded here so nobody claims otherwise from reading a main.go.",
}

func binaries(t *testing.T) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-f", "{{.Name}} {{.ImportPath}}", "./cmd/...")
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list ./cmd/...: %v\n%s", err, stderr)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, path, ok := strings.Cut(line, " ")
		if !ok || name != "main" {
			continue
		}
		names = append(names, path[strings.LastIndex(path, "/")+1:])
	}
	sort.Strings(names)
	if len(names) < 5 {
		t.Fatalf("found %d main packages under ./cmd; the census is reading nothing", len(names))
	}
	return names
}

func reachesPGX(t *testing.T, binary string) bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./cmd/"+binary)
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/%s: %v", binary, err)
	}
	deps := strings.Split(string(out), "\n")
	if len(deps) < 20 {
		t.Fatalf("cmd/%s resolved %d dependencies; the graph did not load", binary, len(deps))
	}
	for _, d := range deps {
		if strings.HasPrefix(d, "github.com/jackc/pgx") {
			return true
		}
	}
	return false
}

func TestTheDatabaseFreeBinariesAreDatabaseFree(t *testing.T) {
	present := map[string]bool{}
	for _, b := range binaries(t) {
		present[b] = true
	}

	for name, why := range dbFree {
		if !present[name] {
			t.Errorf("dbFree names cmd/%s, which does not exist. Remove the entry: a register that "+
				"describes a tree that is gone is worse than no register.", name)
			continue
		}
		if reachesPGX(t, name) {
			t.Errorf("cmd/%s reaches github.com/jackc/pgx, but the register says it must not:\n  %s\n\n"+
				"Either the new import is wrong for this binary, or the part it needs should be split "+
				"into a leaf package the way internal/common/jwksverify came out of "+
				"internal/common/middleware and internal/common/redisclient came out of "+
				"internal/common/database.", name, why)
		}
	}

	for name := range notes {
		if !present[name] {
			t.Errorf("notes names cmd/%s, which does not exist; remove the entry", name)
			continue
		}
		if !reachesPGX(t, name) {
			t.Errorf("notes says cmd/%s reaches the driver and explains why, but it no longer does. "+
				"Move it to dbFree -- the explanation is now wrong, and the binary earned the stronger "+
				"guarantee.", name)
		}
	}
}
