// Command tablewriters finds tables the product reads and nothing writes.
//
// Usage:
//
//	tablewriters [-fail] [-census] <dir>...
//
// THE SHAPE. A dashboard card reads api_usage_metrics for total requests,
// average latency and error rate. The table is created by migration v54 with
// exactly the columns an hourly request aggregate needs. Nothing in the tree
// has ever inserted a row into it -- no handler, no worker, no migration seed.
// So the card reports 0 requests, 0 ms and 0% on every install that has ever
// run, and those three zeros are presented as measurements.
//
// This is the same defect as a control that displays without enforcing, one
// layer down: a table with no writer is a measurement that cannot measure. It
// is invisible to every other check the repository has. The rows are absent
// rather than wrong, so:
//
//   - the SQL is valid, so tools/sqlprepare passes it;
//   - the query carries its tenant predicate, so tools/orgscope passes it;
//   - the handler returns 200 with a well-formed body, so a contract test and
//     any HTTP-level test pass it;
//   - COUNT(*) of an empty table is 0, not an error, so nothing is logged.
//
// The only thing that can see it is a census: hold the set of tables the schema
// has next to the set of tables the code writes, and subtract.
//
// WHY THE SET IS DERIVED. Both halves come from the tree rather than a list
// somebody maintains, for the reason tools/orgscope was inverted: a table
// nobody remembered to add to a list is not "unchecked" in a way anyone can
// see, it is invisible. The live-table set is folded from the migration
// registry in version order (CREATE adds, DROP removes, RENAME moves), and the
// writer/reader sets come from the SQL string literals in the Go sources.
//
// LITERALS, NOT LINES. The scan reads string literals out of the AST rather
// than grepping the file, because prose about SQL is not SQL. internal/admin's
// analytics handler carries a comment quoting the query a previous fix deleted
// --
//
//	// SELECT feature_name, total_users, trend FROM feature_adoption ...
//
// -- and a line-based scan reads that as a live read of a table dropped two
// migrations ago. The first draft of this census did exactly that and reported
// three tables that no longer exist.
//
// TWO FINDINGS:
//
//	read, never written    -- the query runs, returns nothing, and the zero
//	                          reaches a user as a number.
//	neither read nor written -- an orphan: DDL, indexes and grants for a table
//	                          no code has ever touched.
//
// A table written only by a migration (a seeded singleton like
// siem_forward_cursor, a reference list) is NOT a finding: the seed is its
// writer, and the census says which migration supplied it.
//
// Findings are registered in known.go with a verdict apiece. A finding absent
// from the register fails the run; an entry that no longer reproduces fails it
// too, so the register can only shrink.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openidx/openidx/internal/migrations"
)

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 if a table is read or referenced by nothing that writes it")
	census := flag.Bool("census", false, "print every live table with its writers and readers")
	flag.Parse()

	dirs := flag.Args()
	if len(dirs) == 0 {
		dirs = []string{"./internal", "./cmd", "./pkg"}
	}

	live, seeded, err := liveTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tablewriters: %v\n", err)
		os.Exit(2)
	}

	use, err := scanUsage(dirs, live)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tablewriters: %v\n", err)
		os.Exit(2)
	}

	if *census {
		printCensus(live, seeded, use)
		return
	}

	findings := report(live, seeded, use)

	// A register entry that no longer reproduces is as much a defect as an
	// unregistered finding: it means the tool stopped seeing something, and a
	// checker that quietly stops checking is the failure mode this repository
	// keeps finding.
	found := make(map[string]bool, len(findings))
	for _, f := range findings {
		found[f.Table] = true
	}
	var stale []string
	for table := range knownUnwritten {
		if !found[table] {
			stale = append(stale, table)
		}
	}
	sort.Strings(stale)

	var unregistered []finding
	for _, f := range findings {
		if _, ok := knownUnwritten[f.Table]; !ok {
			unregistered = append(unregistered, f)
		}
	}

	for _, f := range unregistered {
		fmt.Printf("%s: %s\n", f.Table, f.Kind)
		fmt.Printf("    created by migration v%d%s\n", f.Origin, f.ReadBy)
		fmt.Printf("    no INSERT, UPDATE, DELETE or COPY names it anywhere outside migrations and tests\n")
	}
	for _, table := range stale {
		fmt.Printf("%s: registered as unwritten, but a writer exists now\n", table)
		fmt.Printf("    remove its entry from tools/tablewriters/known.go\n")
	}

	fmt.Fprintf(os.Stderr, "tablewriters: %d live table(s), %d unwritten, %d registered, %d new, %d stale\n",
		len(live), len(findings), len(knownUnwritten), len(unregistered), len(stale))

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0) {
		os.Exit(1)
	}
}

type finding struct {
	Table  string
	Kind   string
	Origin int
	ReadBy string
}

func report(live map[string]int, seeded map[string]int, use map[string]*usage) []finding {
	var out []finding
	for table, origin := range live {
		if _, ok := seeded[table]; ok {
			continue // a migration puts the rows there
		}
		u := use[table]
		if u != nil && len(u.Writers) > 0 {
			continue
		}
		f := finding{Table: table, Origin: origin, Kind: "neither read nor written"}
		if u != nil && len(u.Readers) > 0 {
			f.Kind = "read, never written"
			f.ReadBy = fmt.Sprintf(", read in %s", strings.Join(u.Readers, ", "))
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

func printCensus(live, seeded map[string]int, use map[string]*usage) {
	names := make([]string, 0, len(live))
	for t := range live {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		u := use[t]
		var w, r int
		if u != nil {
			w, r = len(u.Writers), len(u.Readers)
		}
		seed := ""
		if v, ok := seeded[t]; ok {
			seed = fmt.Sprintf(" seeded=v%d", v)
		}
		fmt.Printf("%-40s created=v%-4d writers=%-2d readers=%-2d%s\n", t, live[t], w, r, seed)
	}
}

// --- the schema half ---------------------------------------------------

var (
	ident         = `(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`
	createTableRE = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident)
	dropTableRE   = regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + ident)
	renameTableRE = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+RENAME\s+TO\s+` + ident)
	insertIntoRE  = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+` + ident)
	lineCommentRE = regexp.MustCompile(`(?m)--[^\n]*`)
	blockCommentR = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// stripSQLComments blanks out -- and /* */ comments, for the same reason the
// AST scan below exists: a migration header explaining a table in prose is not
// DDL, and reading it as DDL teaches the census the opposite of the truth.
func stripSQLComments(sql string) string {
	sql = blockCommentR.ReplaceAllString(sql, " ")
	return lineCommentRE.ReplaceAllString(sql, "")
}

// liveTables folds the migration registry in version order and returns the
// tables that exist at the end, each with the version that created it, plus
// the tables a migration seeds rows into.
func liveTables() (live map[string]int, seeded map[string]int, err error) {
	all := migrations.All()
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("migration registry is empty")
	}
	live, seeded = foldTables(all)
	return live, seeded, nil
}

// foldTables applies each migration's Up DDL in version order. Only the Up
// half is read: a Down that drops a table is what a rollback would do, not what
// the schema is, and reading both makes every table look dropped.
func foldTables(all []*migrations.Migration) (live, seeded map[string]int) {
	sorted := make([]*migrations.Migration, len(all))
	copy(sorted, all)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Version < sorted[j].Version })

	live = make(map[string]int, 256)
	seeded = make(map[string]int, 32)
	for _, m := range sorted {
		sql := stripSQLComments(m.UpSQL)
		for _, match := range createTableRE.FindAllStringSubmatch(sql, -1) {
			if _, exists := live[match[1]]; !exists {
				live[match[1]] = m.Version
			}
		}
		for _, match := range renameTableRE.FindAllStringSubmatch(sql, -1) {
			if origin, exists := live[match[1]]; exists {
				delete(live, match[1])
				live[match[2]] = origin
			}
		}
		for _, match := range dropTableRE.FindAllStringSubmatch(sql, -1) {
			delete(live, match[1])
			delete(seeded, match[1])
		}
		for _, match := range insertIntoRE.FindAllStringSubmatch(sql, -1) {
			seeded[match[1]] = m.Version
		}
	}
	return live, seeded
}

// --- the code half -----------------------------------------------------

type usage struct {
	Writers []string
	Readers []string
}

// scanUsage walks dirs for non-test Go files and records, per table, the files
// whose SQL literals write it and the files whose SQL literals read it.
func scanUsage(dirs []string, live map[string]int) (map[string]*usage, error) {
	// One regexp per table is too slow over the whole tree; instead each
	// literal is scanned once for the verbs, and the captured name looked up.
	writeRE := regexp.MustCompile(`(?is)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|COPY|TRUNCATE(?:\s+TABLE)?|MERGE\s+INTO)\s+` + ident)
	readRE := regexp.MustCompile(`(?is)\b(?:FROM|JOIN)\s+` + ident)

	out := make(map[string]*usage, len(live))
	add := func(table, file string, writer bool) {
		if _, ok := live[table]; !ok {
			return
		}
		u := out[table]
		if u == nil {
			u = &usage{}
			out[table] = u
		}
		list := &u.Readers
		if writer {
			list = &u.Writers
		}
		for _, seen := range *list {
			if seen == file {
				return
			}
		}
		*list = append(*list, file)
	}

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", "testdata":
					return fs.SkipDir
				}
				// Migrations are the schema, not a consumer of it: counting
				// their DDL as a read would make every table look used.
				if path == filepath.Join(dir, "migrations") || strings.HasSuffix(path, "/internal/migrations") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			literals, perr := sqlLiterals(path)
			if perr != nil {
				return perr
			}
			for _, lit := range literals {
				sql := stripSQLComments(lit)
				for _, m := range writeRE.FindAllStringSubmatch(sql, -1) {
					add(m[1], path, true)
				}
				for _, m := range readRE.FindAllStringSubmatch(sql, -1) {
					add(m[1], path, false)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// sqlLiterals returns every string literal in a Go file.
//
// A parse failure is fatal rather than skipped. The first version of the
// sibling sweep in tools/sqlprepare returned nil here, and the first thing that
// happened was a stray backtick in a comment turning the scan off for a whole
// file -- while the run reported one FEWER finding, which reads exactly like a
// fix.
func sqlLiterals(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		out = append(out, s)
		return true
	})
	return out, nil
}
