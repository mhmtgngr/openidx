// Command orgscope reports SQL statements that target a v2.0-scoped
// table but lack an org_id reference. It is the static helper the
// v1.6.0 Foundation milestone introduces (see
// docs/v2-multitenancy-design.md) for the v2.0 multi-tenancy epic.
//
// Usage:
//
//	orgscope [-fail] <dir>...
//
// The tool walks each <dir> recursively, parses .go files, finds
// string-literal SQL arguments to function calls, and reports any
// scoped-table reference that has no `org_id` mention. _test.go files
// are skipped (test fixtures are allowed to mock without scoping).
//
// In v1.6.0 the tool is informational: it always exits 0 unless -fail
// is set. v1.7.0 will run it with -fail in CI as the enforcement gate
// after each service-layer migration.
//
// Heuristic, not a parser. False positives and false negatives are
// possible — see the sqlcheck.go comment for the trade-offs.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	failOnFindings := flag.Bool("fail", false, "exit non-zero when findings exist (default off in v1.6.0)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-fail] <dir>...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var total int
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

	fmt.Fprintf(os.Stderr, "\norgscope: %d possible unscoped queries across %d dir(s)\n",
		total, flag.NArg())

	if *failOnFindings && total > 0 {
		os.Exit(1)
	}
}
