// sqlprepare asks PostgreSQL whether the SQL in this repository can run.
//
// WHY THIS EXISTS. A CI run's Postgres log carried these, from a job that
// finished green:
//
//	ERROR:  column "request_count" does not exist
//	ERROR:  column "revoked_at" does not exist
//	ERROR:  malformed array literal: "[]"
//
// api_usage_metrics has (endpoint, method, service, status_code, count,
// avg_latency_ms, hour). The handler that draws the API-usage dashboard selects
// request_count, error_count and recorded_at from it -- three columns that have
// never existed in any migration. Every one of its four queries fails, three of
// them through a bare .Scan() whose error is discarded and one through
// `if err == nil`, so the endpoint answers 0 requests, 0 errors, 0 ms latency
// and an empty endpoint list. A screen of zeros is indistinguishable from a
// quiet install.
//
// That is this branch's defect class with a new disguise: not a control that
// displays without enforcing, but a MEASUREMENT that displays without
// measuring. And the file already knew -- twenty lines below, a comment records
// the identical defect found in feature_adoption ("no total_users column, and
// no migration ever added either ... the handler's `if err == nil` swallowed
// it"). One function was fixed; its neighbour was not read.
//
// A reviewer cannot catch this. The query is syntactically perfect, the Go
// compiles, the test suite passes, and the failure is a runtime error the
// handler is written to ignore. Only the database knows, so the database is
// what this tool asks.
//
// HOW. Every SQL literal in the tree is handed to PREPARE against a Postgres
// with all migrations applied. PREPARE parses, resolves every name against the
// catalog and plans the statement, without executing it or touching a row, so a
// missing column, a missing table, a type that cannot be coerced or an
// aggregate outside its GROUP BY all surface -- and nothing else does.
//
// WHAT IS NOT A FINDING, stated because a checker that cries wolf gets deleted:
//
//   - A syntax error means the literal is a FRAGMENT -- the head of a query
//     assembled with += at runtime. PREPARE cannot judge half a statement, so
//     these are skipped rather than reported.
//   - "could not determine data type of parameter $n" and "inconsistent types
//     deduced for parameter $n" are limits of PREPARE itself: the parameter has
//     no context to infer from. The driver supplies the type at execution.
//   - A literal carrying fmt verbs (%s, %d) is a template, not a statement.
//
// Everything else is a query that cannot succeed against the schema this repo
// creates, and the register in known.go carries the ones already found, each
// with its verdict. A finding that is not in the register fails the run; a
// register entry that no longer reproduces fails it too, so the list can only
// shrink.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Roots swept for SQL. internal/migrations is excluded: it IS the schema, and
// its DDL is not a prepared statement.
var defaultRoots = []string{"internal", "cmd", "pkg", "tools"}

var skipDirs = map[string]bool{
	"migrations":   true,
	"node_modules": true,
	"vendor":       true,
	"testdata":     true,
}

type finding struct {
	File   string
	Line   int
	SQL    string
	Code   string // SQLSTATE
	Detail string
}

func (f finding) fingerprint() string {
	sum := sha256.Sum256([]byte(normalize(f.SQL)))
	return f.File + "#" + hex.EncodeToString(sum[:])[:12]
}

func main() {
	var (
		failOnFindings = flag.Bool("fail", false, "exit non-zero on a finding the register does not carry")
		verbose        = flag.Bool("v", false, "also list what was skipped and why")
		dsn            = flag.String("dsn", "", "PostgreSQL DSN (default: $DATABASE_URL)")
	)
	flag.Parse()

	conn := *dsn
	if conn == "" {
		conn = os.Getenv("DATABASE_URL")
	}
	if conn == "" {
		fmt.Fprintln(os.Stderr, "sqlprepare: no DSN. Pass -dsn or set DATABASE_URL to a database with the migrations applied.")
		os.Exit(2)
	}

	roots := flag.Args()
	if len(roots) == 0 {
		roots = defaultRoots
	}

	stmts, err := collect(roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlprepare: %v\n", err)
		os.Exit(2)
	}

	ctx := context.Background()
	db, err := pgx.Connect(ctx, conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlprepare: connect: %v\n", err)
		os.Exit(2)
	}
	defer db.Close(ctx)

	var findings []finding
	skipped := map[string]int{}

	for i, s := range stmts {
		_, perr := db.Prepare(ctx, "sqlprepare_"+strconv.Itoa(i), s.SQL)
		if perr == nil {
			continue
		}
		code, detail := pgErr(perr)
		if reason, skip := skipReason(code, detail, s.SQL, s.Continued); skip {
			skipped[reason]++
			if *verbose {
				fmt.Printf("skip  %s:%d  %s (%s)\n", s.File, s.Line, reason, code)
			}
			continue
		}
		findings = append(findings, finding{File: s.File, Line: s.Line, SQL: s.SQL, Code: code, Detail: detail})
	}

	sort.Slice(findings, func(a, b int) bool {
		if findings[a].File != findings[b].File {
			return findings[a].File < findings[b].File
		}
		return findings[a].Line < findings[b].Line
	})

	seen := map[string]bool{}
	var novel []finding
	for _, f := range findings {
		fp := f.fingerprint()
		if _, ok := knownBroken[fp]; ok {
			seen[fp] = true
			continue
		}
		novel = append(novel, f)
	}

	var stale []string
	for fp := range knownBroken {
		if !seen[fp] {
			stale = append(stale, fp)
		}
	}
	sort.Strings(stale)

	fmt.Printf("sqlprepare: %d SQL literal(s) prepared, %d finding(s) (%d already registered, %d new), %d stale register entr(ies)\n",
		len(stmts), len(findings), len(findings)-len(novel), len(novel), len(stale))
	for reason, n := range skipped {
		fmt.Printf("  skipped %4d  %s\n", n, reason)
	}

	for _, f := range novel {
		fmt.Printf("\n%s:%d: [%s] %s\n", f.File, f.Line, f.Code, f.Detail)
		fmt.Printf("    fingerprint: %s\n", f.fingerprint())
		fmt.Printf("    %s\n", firstLines(f.SQL, 3))
	}
	for _, fp := range stale {
		fmt.Printf("\nstale register entry: %s\n", fp)
		fmt.Printf("    %s\n", knownBroken[fp])
		fmt.Printf("    It no longer reproduces. Delete the entry -- a register that keeps fixed\n")
		fmt.Printf("    entries stops describing anything.\n")
	}

	if *failOnFindings && (len(novel) > 0 || len(stale) > 0) {
		fmt.Fprintf(os.Stderr, "\nsqlprepare: %d new finding(s), %d stale entr(ies)\n", len(novel), len(stale))
		os.Exit(1)
	}
}

// skipReason names the PREPARE outcomes that say something about this tool's
// reach rather than about the query.
func skipReason(code, detail, sql string, continued bool) (string, bool) {
	switch code {
	case "42601":
		return "fragment of a query assembled at runtime (syntax error alone)", true
	case "42P18", "42P08":
		return "parameter type not inferable by PREPARE (the driver supplies it)", true
	case "42803":
		// A grouping error on a literal the code appends to is the missing
		// GROUP BY that arrives in the suffix. internal/governance builds its
		// access-review list that way -- the aggregate is in the literal, the
		// GROUP BY three statements later -- and preparing the first half
		// alone reported "ar.id must appear in the GROUP BY clause" for a
		// query that groups correctly at runtime. A grouping error on a
		// COMPLETE statement is still a finding.
		if continued {
			return "first half of a query the code appends clauses to", true
		}
	case "42P01":
		// 42P01 covers two different things and only one of them is a finding.
		//
		// "relation X does not exist" is the class this tool exists for. But
		// "missing FROM-clause entry for table X" on a literal that contains no
		// FROM clause AT ALL is not a statement -- it is a SELECT list. The
		// unified audit reader keeps one as the search argument of a
		// strings.Replace that swaps the column list for COUNT(*), and the
		// first version of this tool prepared it, reported it, and I wrote it
		// into the register with a verdict ("the export returns an error the
		// caller discards") that was not true of anything. Measured since: the
		// Replace fires and the count query it builds is valid.
		//
		// The two cannot be confused, because a statement that names a missing
		// table always has the FROM clause it names it in.
		if strings.Contains(detail, "missing FROM-clause entry") && !fromClauseRE.MatchString(sql) {
			return "SELECT list used as a search string, not a statement (no FROM clause)", true
		}
	}
	return "", false
}

// fromClauseRE finds a FROM keyword outside of a string literal. Crude on
// purpose: the question is only whether the text has a FROM clause at all.
var fromClauseRE = regexp.MustCompile(`(?is)\bFROM\b`)

func pgErr(err error) (code, detail string) {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		msg := pe.Message
		if pe.Detail != "" {
			msg += " -- " + pe.Detail
		}
		return pe.Code, msg
	}
	return "?", strings.Join(strings.Fields(err.Error()), " ")
}

type sqlLiteral struct {
	File string
	Line int
	SQL  string
	// Continued marks a literal the code appends to (`q := ` + "`SELECT …`" + `;
	// q += ` + "`GROUP BY …`" + `). PREPARE sees only the first half, so an
	// error a suffix would have supplied -- a GROUP BY that arrives later, a
	// clause the builder adds -- is a property of the fragment and not of the
	// statement that reaches the database. Errors that no suffix can explain,
	// a missing column or a missing table, are still findings on a fragment.
	Continued bool
}

// collect walks the roots and returns every string literal that begins a SQL
// statement. Matching on the AST rather than on the file text keeps a sentence
// in a comment that starts with "SELECT" out of the sweep.
func collect(roots []string) ([]sqlLiteral, error) {
	var out []sqlLiteral
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if skipDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				// A parse failure must be loud. The first draft returned nil
				// here, and the first thing that happened was a stray backtick
				// in a comment turning off the sweep for the whole file --
				// while the run reported one FEWER finding, which reads exactly
				// like a fix. A guard that goes quiet on a file it cannot read
				// is the defect it was written to catch.
				return fmt.Errorf("%s: %w", path, perr)
			}
			// Which variables the file appends to, so a literal assigned to
			// one can be recognised as the first half of a query.
			continued := continuedVars(f)

			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				val, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				if !isStatement(val) {
					return true
				}
				out = append(out, sqlLiteral{
					File:      filepath.ToSlash(path),
					Line:      fset.Position(lit.Pos()).Line,
					SQL:       strings.TrimSuffix(strings.TrimSpace(val), ";"),
					Continued: continued[assignedTo(f, lit)],
				})
				return true
			})
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return out, nil
}

// continuedVars returns the names of variables the file appends a string to
// with `+=`. A query built that way reaches the database with more clauses than
// the literal carries.
func continuedVars(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		asn, ok := n.(*ast.AssignStmt)
		if !ok || asn.Tok != token.ADD_ASSIGN {
			return true
		}
		for _, lhs := range asn.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// assignedTo returns the name of the variable a literal is assigned to, or "".
func assignedTo(f *ast.File, lit *ast.BasicLit) string {
	var name string
	ast.Inspect(f, func(n ast.Node) bool {
		asn, ok := n.(*ast.AssignStmt)
		if !ok || len(asn.Lhs) != 1 || len(asn.Rhs) != 1 || asn.Rhs[0] != ast.Expr(lit) {
			return true
		}
		if id, ok := asn.Lhs[0].(*ast.Ident); ok {
			name = id.Name
		}
		return false
	})
	return name
}

var statementHeads = []string{"select ", "insert into ", "update ", "delete from ", "with "}

// isStatement reports whether a literal opens a statement PREPARE can plan. A
// literal carrying fmt verbs is a template that never reaches the database in
// this form.
func isStatement(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	// A comment header is normal in this repo ("-- Migration 026: ...").
	for strings.HasPrefix(t, "--") {
		nl := strings.IndexByte(t, '\n')
		if nl < 0 {
			return false
		}
		t = strings.TrimSpace(t[nl+1:])
	}
	t = strings.Join(strings.Fields(t), " ") + " "
	var head bool
	for _, h := range statementHeads {
		if strings.HasPrefix(t, h) {
			head = true
			break
		}
	}
	if !head {
		return false
	}
	for _, verb := range []string{"%s", "%d", "%v", "%q", "%w", "%f", "%t"} {
		if strings.Contains(s, verb) {
			return false
		}
	}

	// An English sentence can open with one of those words ("select the tenant
	// before writing", "update client"). PREPARE would call it a syntax error
	// and the run would skip it as a fragment, so nothing breaks -- but a skip
	// bucket padded with prose is a bucket nobody reads, and this tool's skips
	// are supposed to stay reviewable. A statement carries SQL structure:
	// a parameter, a parenthesis, a comma, a quoted literal, or a clause
	// keyword. The exception is the handful of two-word probes ("SELECT 1"),
	// which have no structure and no table and cannot carry this defect either
	// way.
	for _, mark := range []string{"$", "(", ",", "'", "\"", " from ", " into ", " set ", " values ", " where ", " join "} {
		if strings.Contains(t, mark) {
			return true
		}
	}
	return len(strings.Fields(t)) <= 3
}

func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func firstLines(s string, n int) string {
	fields := strings.Split(normalize(s), " ")
	if len(fields) > 14*n {
		fields = fields[:14*n]
		return strings.Join(fields, " ") + " ..."
	}
	return strings.Join(fields, " ")
}
