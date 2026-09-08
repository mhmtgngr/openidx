// Command silentwrite finds writes whose failure nobody learns about.
//
// THE DEFECT. This statement changes the database, and this code cannot tell
// whether it did:
//
//	_, _ = s.db.Pool.Exec(ctx,
//	    `UPDATE access_requests SET status='expired' WHERE id=$1`, reqID)
//
// A write can fail for every reason a read can -- a column that is not there, a
// row-level policy that refused, a constraint, a connection that died, a
// transaction already aborted -- and the caller carries on as if it had
// succeeded. Where the caller then answers 200, the API has reported an outcome
// the database declined to record.
//
// This is not a style rule about unchecked errors, and it is not a claim that
// every write must be checked. A great many of these are best-effort by design:
// a last-seen timestamp, a queue counter, a telemetry row. Losing one costs a
// stale number and nothing else, and wrapping each in an error path nobody reads
// would be worse code.
//
// The point is that "best-effort" is a JUDGEMENT, and the tree records it
// nowhere. `_, _ =` is Go's spelling for "I meant to drop this", which is
// exactly as true of the timestamp as of the revoked credential, and a reader
// cannot tell them apart. So: say which it is, next to the code, the way
// //orgscope:ignore already works in this repository.
//
// WHAT COUNTS AS A FINDING. Deliberately narrow, because a gate that reports
// correct code is one somebody turns off:
//
//   - The statement must be a literal string whose first keyword is INSERT,
//     UPDATE or DELETE. A SET or a SELECT through Exec is session setup, not a
//     write; those are counted and reported, never failed on.
//   - The error must be discarded SYNTACTICALLY -- `_, _ = ...Exec(...)`, or the
//     call standing alone as a statement. A `_, err := ...` that some later
//     branch checks is not a finding: proving it unread needs flow analysis, and
//     a guess in that direction would report working code.
//
// CLEARING A FINDING. Handle the error, or write the reason above the call:
//
//	//silentwrite:ok a stale last_seen_at costs a wrong "last active" column
//	//silentwrite:ok and nothing else; the session itself is authoritative.
//	_, _ = s.db.Pool.Exec(ctx, `UPDATE users SET last_seen_at = NOW() ...`)
//
// The reason must be long enough to be a reason. "best effort" is not one --
// it restates the shape without saying what is lost.
//
// Usage:
//
//	go run ./tools/silentwrite [-fail] [-census] [dir ...]
package main

import (
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
)

// minReason is the length below which a marker is not saying anything. Long
// enough to force a clause about what is lost; short enough not to be busywork.
const minReason = 60

// marker is the comment that clears a finding.
const marker = "//silentwrite:ok"

func main() {
	var (
		failOnFindings = flag.Bool("fail", false, "exit non-zero if any write discards its error without a reason")
		census         = flag.Bool("census", false, "list every discarded Exec, cleared or not")
	)
	flag.Parse()

	dirs := flag.Args()
	if len(dirs) == 0 {
		dirs = []string{"./internal", "./cmd", "./pkg"}
	}

	var findings []finding
	var cleared, nonWrites, scanned int

	for _, dir := range dirs {
		err := filepath.Walk(strings.TrimPrefix(dir, "./"), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				switch info.Name() {
				case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanned++
			f, c, n, ferr := scanFile(path)
			if ferr != nil {
				return nil
			}
			findings = append(findings, f...)
			cleared += c
			nonWrites += n
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "silentwrite: %v\n", err)
			os.Exit(2)
		}
	}

	if scanned == 0 {
		fmt.Fprintf(os.Stderr, "silentwrite: scanned no files; the directories given do not hold Go source\n")
		os.Exit(2)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	if *census {
		for _, f := range findings {
			fmt.Printf("  UNMARKED  %s:%d  %s %s\n", f.File, f.Line, f.Verb, f.Table)
		}
	}

	fmt.Printf("silentwrite: %d write(s) discard their error without a reason, %d carry one, %d non-write Exec(s) not counted\n",
		len(findings), cleared, nonWrites)

	if len(findings) == 0 {
		return
	}

	fmt.Printf("\nEach of these changes the database and cannot tell whether it did:\n\n")
	for _, f := range findings {
		fmt.Printf("  %s:%d  %s %s\n", f.File, f.Line, f.Verb, f.Table)
	}
	fmt.Printf(`
Handle the error where the caller's answer depends on the write, or say why it
does not, immediately above the call:

    %s <what is lost when this write fails, and why that is acceptable>

At least %d characters, because "best effort" restates the shape without saying
what is lost -- which is the thing a reader cannot work out for themselves.
`, marker, minReason)

	if *failOnFindings {
		os.Exit(1)
	}
}

type finding struct {
	File  string
	Line  int
	Verb  string
	Table string
}

// execName matches the database call this gate is about. Exec and ExecContext
// cover pgx pools, transactions and database/sql alike.
var execName = regexp.MustCompile(`^(Exec|ExecContext)$`)

// firstKeyword pulls the leading SQL verb out of a literal statement, skipping
// leading whitespace, line comments and a leading CTE.
var firstKeyword = regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*)*(?:WITH\b.*?\)\s*)?(\w+)`)

// tableName finds the target of a write, for the report only.
var tableName = regexp.MustCompile(`(?is)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"?([\w.]+)"?`)

func scanFile(path string) (findings []finding, cleared, nonWrites int, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, 0, 0, err
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	lines := strings.Split(string(src), "\n")

	report := func(call *ast.CallExpr) {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !execName.MatchString(sel.Sel.Name) {
			return
		}
		sql, ok := literalSQL(call)
		if !ok {
			// A statement built elsewhere. This gate reads literals only, the
			// same limit tools/zeroanswer works under and for the same reason:
			// what it cannot read, it must not judge.
			return
		}
		verb, table := classify(sql)
		if verb == "" {
			nonWrites++
			return
		}
		line := fset.Position(call.Pos()).Line
		if hasMarker(lines, line) {
			cleared++
			return
		}
		findings = append(findings, finding{File: path, Line: line, Verb: verb, Table: table})
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			// `_, _ = pool.Exec(...)` and its := form.
			if len(v.Rhs) != 1 || !allBlank(v.Lhs) {
				return true
			}
			if call, ok := v.Rhs[0].(*ast.CallExpr); ok {
				report(call)
			}
		case *ast.ExprStmt:
			// `pool.Exec(...)` standing alone: both results dropped.
			if call, ok := v.X.(*ast.CallExpr); ok {
				report(call)
			}
		}
		return true
	})
	return findings, cleared, nonWrites, nil
}

func allBlank(lhs []ast.Expr) bool {
	if len(lhs) == 0 {
		return false
	}
	for _, e := range lhs {
		id, ok := e.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return true
}

// literalSQL returns the statement when it is written at the call site.
func literalSQL(call *ast.CallExpr) (string, bool) {
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			// A raw string with a backtick body that Unquote refuses is still
			// readable by trimming the quotes.
			s = strings.Trim(lit.Value, "`\"")
		}
		if firstKeyword.MatchString(s) {
			return s, true
		}
	}
	return "", false
}

// classify returns the write verb and its table, or "" when the statement does
// not modify a table.
func classify(sql string) (verb, table string) {
	m := firstKeyword.FindStringSubmatch(sql)
	if m == nil {
		return "", ""
	}
	switch strings.ToUpper(m[1]) {
	case "INSERT", "UPDATE", "DELETE":
		verb = strings.ToUpper(m[1])
	default:
		return "", ""
	}
	if t := tableName.FindStringSubmatch(sql); t != nil {
		table = t[1]
	}
	return verb, table
}

// hasMarker reports whether a reason of usable length sits immediately above
// the call. Immediately, because a marker several statements up would come to
// cover writes it was never written about.
func hasMarker(lines []string, line int) bool {
	reason := ""
	for i := line - 2; i >= 0 && i >= line-8; i-- {
		text := strings.TrimSpace(lines[i])
		if strings.HasPrefix(text, marker) {
			reason = strings.TrimSpace(strings.TrimPrefix(text, marker)) + " " + reason
			continue
		}
		// A continuation line of the same comment block keeps the run going;
		// anything else ends it.
		if reason != "" && strings.HasPrefix(text, "//") {
			reason = strings.TrimSpace(strings.TrimPrefix(text, "//")) + " " + reason
			continue
		}
		if reason != "" {
			break
		}
		// Allow the call to be preceded by the rest of its own multi-line
		// argument list before the comment block begins.
		if text == "" || strings.HasPrefix(text, "//") {
			continue
		}
		break
	}
	return len(strings.TrimSpace(reason)) >= minReason
}
