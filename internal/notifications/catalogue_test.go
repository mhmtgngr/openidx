package notifications

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The catalogue held against the tree, and the preference held against every
// writer.
//
// Two things were true of this product's notification preferences and neither
// was visible from the page:
//
//  1. The seven switches the console offered -- access_request, security_alert,
//     session_revoked, review_assigned, group_request, password_expiry,
//     mfa_change -- named types nothing has ever sent. The four types it does
//     send appeared on no switch.
//  2. Four of the six senders never went through CreateNotification, so they
//     never called isNotificationEnabled. They wrote `INSERT INTO
//     notifications` directly, as set-based fan-outs over every admin, every
//     user in an org, or every user a finding named. A preference no writer
//     reads is not a preference.
//
// So this file checks both: every catalogue entry has a sender and every sent
// type is in the catalogue, and every statement that writes the notifications
// table consults notification_preferences in the same breath.

func scanTree(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
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
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			out[filepath.ToSlash(path)] = f
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return out
}

// catalogueConstNames maps a constant's identifier to its value, read out of
// catalogue.go so there is no second list to keep in step.
func catalogueConstNames(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "catalogue.go", nil, 0)
	if err != nil {
		t.Fatalf("parse catalogue.go: %v", err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, name := range vs.Names {
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
						out[name.Name] = v
					}
				}
			}
		}
	}
	if len(out) != len(TypeCatalogue) {
		t.Fatalf("catalogue.go declares %d constants for %d catalogue entries", len(out), len(TypeCatalogue))
	}
	return out
}

// Every type a user can switch off is one something sends.
func TestEveryCatalogueTypeHasASender(t *testing.T) {
	consts := catalogueConstNames(t)
	files := scanTree(t)

	used := map[string][]string{}
	for path, f := range files {
		if strings.HasSuffix(path, "/notifications/catalogue.go") {
			continue // the declaration is not a use
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var name string
			switch x := n.(type) {
			case *ast.SelectorExpr:
				name = x.Sel.Name
			case *ast.Ident:
				name = x.Name
			default:
				return true
			}
			if v, ok := consts[name]; ok {
				used[v] = append(used[v], path)
			}
			return true
		})
	}

	for _, e := range TypeCatalogue {
		if len(used[e.Type]) == 0 {
			t.Errorf("%s is offered as a switch and nothing sends it: the user would be "+
				"turning off a notification that does not exist", e.Type)
		}
	}
}

// And nothing is sent that a user cannot switch off. The type reaches the
// database either as an argument to the service or as a bind parameter in a
// set-based INSERT, so a string literal in the type position is the shape this
// forbids -- it is how 'broadcast', 'security' and 'device_trust' came to be
// unswitchable.
func TestNoNotificationTypeIsAnInlineLiteral(t *testing.T) {
	insert := regexp.MustCompile(`(?is)INSERT\s+INTO\s+notifications\b`)
	// The type column sits third in every one of these writes; an inlined value
	// shows up as a quoted string in the SELECT list right after the channel.
	inlineType := regexp.MustCompile(`(?is)'in_app'\s*,\s*'[a-z_]+'|\$\d+\s*,\s*'[a-z_]+'\s*,\s*\$`)

	for path, f := range scanTree(t) {
		if strings.Contains(path, "/notifications/") {
			continue // the service's own INSERT takes the type as a Go field
		}
		for _, lit := range stringLiterals(f) {
			if !insert.MatchString(lit) {
				continue
			}
			if m := inlineType.FindString(lit); m != "" {
				t.Errorf("%s: writes notifications with an inline type (%s). Pass a "+
					"catalogue constant as a bind parameter, or the type can drift out of "+
					"the list a user is offered", path, strings.Join(strings.Fields(m), " "))
			}
		}
	}
}

// The preference is only a preference if the writer reads it. Every statement
// that writes the notifications table outside this package must carry the
// notification_preferences predicate; inside it, CreateNotification does the
// same check in Go.
func TestEveryNotificationWriterConsultsThePreference(t *testing.T) {
	insert := regexp.MustCompile(`(?is)INSERT\s+INTO\s+notifications\b`)
	var offenders []string
	for path, f := range scanTree(t) {
		if strings.Contains(path, "/notifications/") {
			continue
		}
		for _, lit := range stringLiterals(f) {
			if !insert.MatchString(lit) {
				continue
			}
			if !strings.Contains(lit, "notification_preferences") {
				offenders = append(offenders, path)
			}
		}
	}
	sort.Strings(offenders)
	for _, path := range offenders {
		t.Errorf("%s: writes notifications without consulting notification_preferences. "+
			"This is the shape that made four senders ignore every switch on the "+
			"preferences page. Add the NOT EXISTS clause, or send through "+
			"notifications.Service", path)
	}
}

// A preference for something this deployment never sends is refused rather than
// stored, because the moment it is stored it is believed.
func TestKnownType(t *testing.T) {
	for _, e := range TypeCatalogue {
		if !KnownType(e.Type) {
			t.Errorf("KnownType(%q) is false for a catalogue entry", e.Type)
		}
	}
	for _, gone := range []string{
		"access_request", "security_alert", "session_revoked",
		"review_assigned", "group_request", "password_expiry", "mfa_change",
	} {
		if KnownType(gone) {
			t.Errorf("KnownType(%q) is true; that is one of the seven the console offered "+
				"and nothing ever sent", gone)
		}
	}
}

// Each entry says what arrives, in the words of the person choosing.
func TestEveryCatalogueEntryDescribesItself(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range TypeCatalogue {
		if seen[e.Type] {
			t.Errorf("%s appears twice", e.Type)
		}
		seen[e.Type] = true
		if e.Title == "" {
			t.Errorf("%s has no title", e.Type)
		}
		if len(e.Description) < 20 || !strings.HasSuffix(e.Description, ".") {
			t.Errorf("%s: description %q does not say what arrives", e.Type, e.Description)
		}
		if len(e.Channels) == 0 {
			t.Errorf("%s names no channel", e.Type)
		}
	}
}

func stringLiterals(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, s)
		}
		return true
	})
	return out
}
