// Command orgscope is the tenant-boundary lint. It answers two questions:
// is every table in the schema classified, and does every query against a
// tenant table carry its org_id.
//
// Usage:
//
//	orgscope [-fail] <dir>...
//	orgscope -census
//
// SCHEMA. The scope of each table is DERIVED from the migration registry
// (ddl.go), not from a hand-written list. Folding every migration's UpSQL in
// version order says, per table, whether it carries org_id and whether it has
// FORCE ROW LEVEL SECURITY. A table with neither org_id nor an entry in
// installWideTables, or with org_id but no belt and no entry in beltExempt,
// is a blocking finding: it is a table nobody has classified.
//
// That inversion is the point. The list this replaced covered ~90 tables of
// 231, and a table nobody remembered to add was not merely unchecked -- it
// was invisible. ispm_findings, ispm_rules, ispm_scores, ai_agents and
// ai_recommendations sat outside it for nine releases while internal/admin
// read, updated and DELETEd them across tenants and this tool reported zero
// findings on every one of those PRs. See migration v138.
//
// QUERIES. The tool walks each <dir> recursively, parses .go files, finds
// string-literal SQL arguments to function calls, and reports any scoped-table
// reference with no org_id mention. _test.go files are skipped (test fixtures
// are allowed to mock without scoping).
//
// A query that is intentionally unscoped -- e.g. an auth-path lookup keyed by
// a globally-unique value before any tenant is resolved, or a write to an
// install-wide table -- can be exempted with an inline directive carrying a
// mandatory reason:
//
//	//orgscope:ignore validated by globally-unique key_hash before tenant resolution
//	db.QueryRow(ctx, `SELECT org_id FROM api_keys WHERE key_hash = $1`, h)
//
// The directive may sit on the same line as the SQL or on the line directly
// above the statement. A reason-less directive does not suppress anything (and
// is reported to stderr), so an exception can never slip in unexplained.
//
// REGISTERS. scoped.go also carries needsScoping, needsBelt and
// predicateAuditPending: findings that predate the inversion, each with what
// the table holds. They are printed with their count on every run but do not
// fail the build, because fixing 95 tables is a migration programme rather
// than a prerequisite for arming the gate. Their sizes are pinned by
// ddl_test.go, so a register can only shrink: a new table cannot be parked on
// one to make it quiet.
//
// -fail exits non-zero when blocking findings exist; CI runs it that way.
// -census prints the derived state of every table.
//
// Heuristic, not a parser. False positives and false negatives are possible --
// see the sqlcheck.go and ddl.go comments for the trade-offs.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
)

func main() {
	failOnFindings := flag.Bool("fail", false, "exit non-zero when findings exist (default off in v1.6.0)")
	showCensus := flag.Bool("census", false, "print the derived table census and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-fail] <dir>...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showCensus {
		printCensus()
		return
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// Schema-level checks first: they answer "is every table classified?",
	// which is prior to "does every query carry its predicate".
	blocking, open := censusFindings(census)
	for _, f := range blocking {
		fmt.Println(f)
	}
	for _, f := range open {
		fmt.Println(f)
	}
	total := len(blocking)

	for _, root := range flag.Args() {
		findings, err := scanDir(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "orgscope: %v\n", err)
			os.Exit(2)
		}
		for _, f := range findings {
			fmt.Println(f)
		}
		total += len(findings)
	}

	fmt.Fprintf(os.Stderr,
		"\norgscope: %d blocking finding(s) across %d dir(s); %d table(s) on the needsScoping/needsBelt registers\n",
		total, flag.NArg(), len(open))

	if *failOnFindings && total > 0 {
		os.Exit(1)
	}
}

// printCensus dumps what the migration DDL says about every live table. It is
// the first thing to run when this tool reports an undeclared table: the
// origin migration says where the table came from, and the org_id/belt columns
// say what is missing.
func printCensus() {
	names := make([]string, 0, len(census))
	for n := range census {
		names = append(names, n)
	}
	sort.Strings(names)

	var scoped, wide, unbelted int
	for _, n := range names {
		t := census[n]
		state := "install-wide"
		if t.HasOrgID {
			state = "scoped"
			scoped++
			if !t.Forced {
				state = "scoped, NO BELT"
				unbelted++
			}
		} else {
			wide++
		}
		declared := ""
		if _, ok := installWideTables[n]; ok {
			declared = "  [declared install-wide]"
		}
		if _, ok := beltExempt[n]; ok {
			declared = "  [declared belt-exempt]"
		}
		fmt.Printf("%-40s v%-4d %-16s%s\n", n, t.Origin, state, declared)
	}
	fmt.Fprintf(os.Stderr, "\norgscope census: %d tables — %d scoped (%d without the RLS belt), %d install-wide\n",
		len(names), scoped, unbelted, wide)
}
