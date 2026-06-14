package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// scanDir recursively scans root and returns one Finding per detected
// unscoped query. Skips vendor/, node_modules/, and _test.go files
// (test SQL is allowed to mock scoped tables without org_id for
// fixtures).
func scanDir(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == "node_modules" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fs, err := scanFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, fs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// ignoreDirectivePrefix marks a query as an intentional, reviewed
// exception to org scoping (e.g. an auth-path lookup keyed by a
// globally-unique value before any tenant is resolved). A reason is
// mandatory: a bare directive does not suppress anything, so an
// exception can never slip in unexplained.
const ignoreDirectivePrefix = "//orgscope:ignore"

// ignoreDirectiveLines returns the set of source lines that carry a
// valid //orgscope:ignore <reason> directive. A reason-less directive
// is reported to stderr and intentionally omitted, so it does not
// suppress its finding.
func ignoreDirectiveLines(f *ast.File, fset *token.FileSet) map[int]bool {
	lines := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(c.Text)
			if !strings.HasPrefix(text, ignoreDirectivePrefix) {
				continue
			}
			reason := strings.TrimSpace(strings.TrimPrefix(text, ignoreDirectivePrefix))
			if reason == "" {
				fmt.Fprintf(os.Stderr, "orgscope: %s: %s requires a reason; ignoring directive\n",
					fset.Position(c.Slash), ignoreDirectivePrefix)
				continue
			}
			lines[fset.Position(c.Slash).Line] = true
		}
	}
	return lines
}

// scanFile parses one .go file and returns findings for SQL literals
// inside call expressions that reference scoped tables without an
// org_id clause.
func scanFile(path string) ([]Finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.AllErrors|parser.ParseComments)
	if err != nil {
		// A syntactically-invalid file shouldn't crash the run; emit a
		// note and continue. The tool doesn't enforce compilability;
		// that's go build's job.
		fmt.Fprintf(os.Stderr, "orgscope: parse %s: %v (skipped)\n", path, err)
		return nil, nil
	}

	// Collect the lines carrying a valid //orgscope:ignore <reason>
	// directive. A finding on that line, or on the line directly
	// below it, is suppressed — covering both the same-line form and
	// the directive-above-a-multi-line-query form.
	ignoredLines := ignoreDirectiveLines(f, fset)

	var findings []Finding
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			sql, err := strconv.Unquote(lit.Value)
			if err != nil {
				// Raw-string backticks fail strconv.Unquote in some Go
				// versions; fall back to manual trim.
				v := lit.Value
				if strings.HasPrefix(v, "`") && strings.HasSuffix(v, "`") && len(v) >= 2 {
					sql = v[1 : len(v)-1]
				} else {
					continue
				}
			}
			if !startsWithSQLKeyword(sql) {
				continue
			}
			litLine := fset.Position(lit.Pos()).Line
			if ignoredLines[litLine] || ignoredLines[litLine-1] {
				continue
			}
			fs := analyzeSQL(sql)
			for i := range fs {
				fs[i].Pos = fset.Position(lit.Pos())
				findings = append(findings, fs[i])
			}
		}
		return true
	})
	return findings, nil
}
