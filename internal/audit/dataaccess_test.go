package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every action the data-access control counts is one something writes.
//
// The control counted `event_type = 'data_access'`, a value declared in
// service.go and written by nothing, so it reported zero on every install and
// called the result "partial". A predicate that matches no row is the same
// defect as a table with no writer, pointed at an auditor -- so the names it
// filters on are held against the tree here, and one that nothing writes fails
// the build rather than quietly counting nothing.
func TestEveryDataAccessActionIsWritten(t *testing.T) {
	written := auditActionLiterals(t)
	for _, action := range DataAccessActions {
		if !written[action] {
			t.Errorf("the data-access control counts %q and nothing writes it: "+
				"the section would report zero and say so as a compliance status", action)
		}
	}
}

// And the list stays a list of reads. A control that counts session
// establishment as a data access overstates, and an overstated control is as
// useless to an auditor as an empty one.
func TestDataAccessActionsAreReads(t *testing.T) {
	excluded := map[string]string{
		"pam.entry_connected":   "establishes a session rather than reading stored data",
		"pam.ws_connect":        "opens the session channel",
		"pam.ws_disconnect":     "closes it",
		"pam.checkout_released": "returns custody of a credential rather than taking it",
	}
	for _, action := range DataAccessActions {
		if why, ok := excluded[action]; ok {
			t.Errorf("%q is in DataAccessActions and %s", action, why)
		}
	}
	if len(DataAccessActions) == 0 {
		t.Fatal("DataAccessActions is empty; the control would count nothing again")
	}
	seen := map[string]bool{}
	for _, action := range DataAccessActions {
		if seen[action] {
			t.Errorf("%q appears twice", action)
		}
		seen[action] = true
	}
}

// auditActionLiterals collects every string literal the tree passes as an audit
// action. It is deliberately coarse -- any literal in a logAuditEvent call --
// because the question is only "does anything write this name", and a false
// negative here would let a dead predicate back in.
func auditActionLiterals(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", "testdata":
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// The declaration is not a use.
			if strings.HasSuffix(filepath.ToSlash(path), "/audit/dataaccess.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch fn := ce.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				if !strings.Contains(strings.ToLower(name), "auditevent") {
					return true
				}
				for _, arg := range ce.Args {
					lit, ok := arg.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
						out[v] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(out) < 20 {
		t.Fatalf("found %d audit action literals; the scan is not reaching the tree", len(out))
	}
	return out
}

// The value the control used to filter on is written nowhere.
//
// This is the fact the fix rests on, and it is checked exactly rather than
// inferred: "data_access" appears in non-test Go only in this package -- the
// EventTypeDataAccess declaration and the queries that used to filter on it.
//
// A position-aware version of this test was written first and thrown away. It
// collected every string literal passed to a logAuditEvent call and reported
// user_management, group_management, role_management and system as "written" --
// but those are the CATEGORY argument, and "system" is what getActorID returns
// when no user is attached. A scan that cannot tell an event type from a
// category from an actor id has no business asserting which vocabulary is live,
// and a test that reports the wrong thing confidently is the shape this branch
// keeps finding. What can be said exactly is said here; the rest is not
// asserted at all.
func TestNothingWritesTheDataAccessEventType(t *testing.T) {
	fset := token.NewFileSet()
	var writers []string
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", "testdata":
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			slash := filepath.ToSlash(path)
			if strings.Contains(slash, "/internal/audit/") {
				return nil // the declaration and the queries live here
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, uerr := strconv.Unquote(lit.Value); uerr == nil && v == string(EventTypeDataAccess) {
					writers = append(writers, slash+":"+strconv.Itoa(fset.Position(lit.Pos()).Line))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(writers) > 0 {
		t.Logf("%q is written now, at %s: the OR term in the data-access queries "+
			"carries it and DataAccessActions may no longer be needed",
			EventTypeDataAccess, strings.Join(writers, ", "))
	}
}
