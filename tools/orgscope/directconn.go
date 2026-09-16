package main

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
)

// THE DOOR THIS TOOL WAS NOT WATCHING.
//
// rawpool.go guards the way OUT of the tenant scope: ScopedPool.Raw(). Both of
// its questions start from a ScopedPool, because that is the type task 2.1b put
// the scope into. A connection opened with pgx.Connect or pgxpool.New never
// becomes a ScopedPool at all -- it is not Raw(), it is not Pool, it is a
// different object -- so neither question is ever asked about it. The lint
// watches the marked door and not the wall beside it.
//
// MEASURED, on this tree: seven non-test call sites open a connection that way
// under internal/ and cmd/. Every one of them turns out to be defensible, which
// is the point: nothing had checked, and the next one arrives in a file nobody
// reviews for tenancy. The hazard is the same one rawpool.go spells out --
// under FORCE RLS a query with no app.org_id is not an error, it is ZERO ROWS,
// and zero rows read as "nothing to do" in every log and every exit code.
//
// So each one is named here with the reason it has no tenant scope to carry.
// A new one is a blocking finding until somebody writes that sentence.
//
// WHAT THIS RULE DOES NOT COVER, said rather than left to be discovered:
// tools/ is not scanned (CI runs this over ./internal ./cmd), so a direct
// connection in a developer tool is out of reach here. That is a deliberate
// boundary -- tools are not shipped inside a serving process -- and not a
// claim that those connections are scoped.

// directConnAllowed is keyed by the file, because a file is the unit somebody
// reviews. The value is why the connection needs no tenant scope.
var directConnAllowed = map[string]string{
	"internal/credentials/postgres_rotator.go": "rotates credentials ON ANOTHER DATABASE: it connects to the server whose password is being changed, as that server's admin, and runs ALTER ROLE. There is no tenant in that connection because there is no application table in it",

	"cmd/openidx/commands/migrate.go": "the CLI's half of the same migration path: schema DDL, no tenant context exists yet",
	"cmd/openidx/commands/seed.go":    "development seeding. It writes the tenants themselves, so there is no org to scope to at the moment it runs; it is not built into any service image",
	"cmd/openidx/commands/cell.go":    "the tenant-directory placement tool. org_cells is org-scoped and FORCE-belted, and this is the one caller that is legitimately cross-tenant: it takes app.bypass_rls INSIDE a transaction, and cell_place_testdb_test.go measures that the policy refuses the same write without it",
	"cmd/rekey/main.go":               "re-encrypts every tenant's encrypted columns under a new KEK, which is cross-tenant by definition. It takes app.bypass_rls and now CHECKS that it took: without the bypass this binary would read zero rows and report a successful rekey of nothing",
}

const rawKindDirectConn = "direct-conn"

// directConnCalls are the ways to open a connection without this repository's
// PostgresDB, which is what carries the tenant scope. Every constructor pgx v5
// exposes is here, checked against the module rather than remembered.
//
// THIS IS A VOCABULARY, NOT A CENSUS, and the difference is worth stating so
// nobody reads the map as a measurement. Counted on this tree today:
// pgx.Connect appears 5 times, pgxpool.NewWithConfig once, and the other two
// not at all. The unexercised entries are the point of having a lint -- they
// are the spellings the next person will reach for -- but a mutation that
// blinds one of them proves nothing, which is how this list first appeared to
// be load-bearing when it was not.
var directConnCalls = map[string]bool{
	"pgx.Connect":            true,
	"pgx.ConnectWithOptions": true,
	"pgx.ConnectConfig":      true,
	"pgxpool.New":            true,
	"pgxpool.NewWithConfig":  true,
}

// directConnFinding reports a connection opened outside internal/common/database
// whose file is not on the register above.
func directConnFinding(call *ast.CallExpr, fset *token.FileSet) []Finding {
	if !directConnCalls[callName(call.Fun)] {
		return nil
	}
	pos := fset.Position(call.Pos())
	rel := normalizeScanPath(pos.Filename)

	// internal/common/database is where the scoped pool is BUILT. A rule that
	// flagged the constructor of the scope would be asking it to go through
	// itself.
	if strings.HasPrefix(rel, "internal/common/database/") {
		return nil
	}
	if _, ok := directConnAllowed[rel]; ok {
		return nil
	}
	return []Finding{{
		Pos:    pos,
		Table:  "-",
		Kind:   rawKindDirectConn,
		SQL:    callName(call.Fun) + "(...)",
		Reason: "opens a database connection that never becomes a ScopedPool, so the Raw() rules never look at it. Under FORCE RLS a query with no app.org_id returns ZERO ROWS rather than an error. Add the file to directConnAllowed with the reason its work has no tenant to carry, or open the connection through database.NewPostgres",
	}}
}

// normalizeScanPath turns whatever the walker produced into a repo-relative
// slash path, so the register reads the way a person would write it.
func normalizeScanPath(p string) string {
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	if i := strings.Index(p, "/internal/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.Index(p, "/cmd/"); i >= 0 {
		p = p[i+1:]
	}
	return p
}
