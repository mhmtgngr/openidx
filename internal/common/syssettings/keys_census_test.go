package syssettings_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A key/value table has a failure mode a table-level check cannot see: the
// table exists, the query is valid, the tenant predicate is right, the handler
// answers 200 — and the key names a row nobody has ever written, so the read
// returns nothing and the caller's default is served as if it were the
// operator's configuration.
//
// That is not hypothetical. Before v1.34.0, eight queries across four packages
// read system_settings under the keys 'settings', 'security',
// 'authentication', 'failed_login_lockout_threshold' and
// 'failed_login_lockout_duration'. Not one of those rows has ever existed; the
// console reads and writes the entire settings document under 'system'. The
// visible results were an idle timeout, absolute timeout, re-auth interval and
// concurrent-session policy the operator could set and the product ignored, a
// lockout that ran on hardcoded numbers, and an ISO 27001 control that
// deducted points for "No security policy configuration found" on installs
// whose policy was fully configured.
//
// This census holds the tree to it. Both halves are derived from the source:
// the keys READ come from the SQL string literals in the Go sources, and the
// keys WRITTEN come from the INSERT/UPSERT literals plus the migration seeds.
// A key that is read and never written fails. It is deliberately not a list of
// approved keys — a list is the thing that let five spellings accumulate.

// systemSettingsKey pulls the key literal out of a query against
// system_settings. Both quoting styles the tree uses are covered: an inline
// 'literal' and a $1 placeholder (whose value is checked separately below).
var (
	reTable   = regexp.MustCompile(`(?is)\bsystem_settings\b`)
	reKeyLit  = regexp.MustCompile(`(?is)\bkey\s*=\s*'([^']*)'`)
	reKeyArg  = regexp.MustCompile(`(?is)\bkey\s*=\s*\$\d+`)
	reInsert  = regexp.MustCompile(`(?is)\binsert\s+into\s+system_settings\b`)
	reValLit  = regexp.MustCompile(`(?is)values\s*\(\s*'([^']*)'`)
	reDelete  = regexp.MustCompile(`(?is)\bdelete\s+from\s+system_settings\b`)
	reColKeys = regexp.MustCompile(`(?is)\(\s*key\s*,`)
)

type keyUse struct {
	key  string
	file string
}

// legacyReadOnlyKeys are the keys read on purpose with no writer, each with the
// reason. It is a register in the shape tools/tablewriters uses: an entry that
// stops reproducing fails the test too, so it can only shrink. It is not an
// allow-list for new keys — a key added here has to earn a sentence saying why
// the product reads something it never writes.
var legacyReadOnlyKeys = map[string]string{
	"oauth_rsa_private_key": "pre-v79 single signing key. internal/oauth reads it once at boot to import the " +
		"legacy key into oauth_signing_keys under its original kid, so tokens minted before the rotatable " +
		"key set existed keep verifying. Nothing writes it any more and nothing should: the row is " +
		"vestigial on any install created after v79 and absent is the normal case.",
}

func TestEverySystemSettingsKeyReadIsAlsoWritten(t *testing.T) {
	root := repoRoot(t)

	var reads, writes []keyUse
	// Placeholder queries ($1) are the shape internal/common/syssettings and
	// internal/admin's repository use: the key is a Go value, not a literal,
	// so it cannot be read out of the SQL. They are counted separately and
	// reported, because a placeholder is how a caller correctly parameterises
	// the key — and how a caller could also hide a bad one.
	var placeholders []keyUse

	walkGoSQL(t, root, func(file, sql string) {
		if !reTable.MatchString(sql) {
			return
		}
		isWrite := reInsert.MatchString(sql) || reDelete.MatchString(sql)
		for _, m := range reKeyLit.FindAllStringSubmatch(sql, -1) {
			u := keyUse{key: m[1], file: file}
			if isWrite {
				writes = append(writes, u)
			} else {
				reads = append(reads, u)
			}
		}
		if reInsert.MatchString(sql) && reColKeys.MatchString(sql) {
			for _, m := range reValLit.FindAllStringSubmatch(sql, -1) {
				writes = append(writes, keyUse{key: m[1], file: file})
			}
		}
		if reKeyArg.MatchString(sql) {
			placeholders = append(placeholders, keyUse{key: "$n", file: file})
		}
	})

	if len(reads) == 0 && len(placeholders) == 0 {
		t.Fatal("scanned no system_settings queries at all — the census is not looking at the tree")
	}

	written := map[string]bool{}
	for _, w := range writes {
		written[w.key] = true
	}
	// Migration seeds are writers too: a row inserted once by a migration is
	// as present as one an upsert maintains.
	for k := range seededKeys(t, root) {
		written[k] = true
	}
	// internal/admin's settings repository is the parameterised writer: its
	// SQL carries $1, so the key is a Go argument rather than a SQL literal.
	// Every key handed to PutRaw is written.
	for k := range repositoryWrittenKeys(t, root) {
		written[k] = true
	}
	// The parameterised readers name their key in Go, not SQL. syssettings.Key
	// is the constant they use, and the seed supplies its row.
	written[keyFromConstant(t, root)] = true

	var orphans []keyUse
	seenOrphan := map[string]bool{}
	for _, r := range reads {
		if written[r.key] {
			continue
		}
		if _, legacy := legacyReadOnlyKeys[r.key]; legacy {
			seenOrphan[r.key] = true
			continue
		}
		orphans = append(orphans, r)
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].key < orphans[j].key })

	for _, o := range orphans {
		t.Errorf("%s reads system_settings under key %q, which nothing in the tree writes and no migration seeds.\n"+
			"    The query is valid and returns no rows on every install, so the caller's default is served as\n"+
			"    the operator's configuration. Read through internal/common/syssettings instead.", o.file, o.key)
	}

	// A register entry that no longer reproduces is as much a defect as an
	// unregistered finding: it means the census stopped seeing something, and a
	// checker that quietly stops checking is the failure mode this repository
	// keeps finding.
	for key := range legacyReadOnlyKeys {
		if !seenOrphan[key] {
			t.Errorf("legacyReadOnlyKeys still lists %q, but nothing reads it without a writer any more — "+
				"remove its entry from keys_census_test.go", key)
		}
	}
}

// TestSyssettingsKeyIsSeeded pins the other half: the key this package reads
// must be one a migration actually creates. Without this the census above
// could be satisfied by everyone agreeing on a key that does not exist.
func TestSyssettingsKeyIsSeeded(t *testing.T) {
	root := repoRoot(t)
	key := keyFromConstant(t, root)
	if !seededKeys(t, root)[key] {
		t.Fatalf("syssettings.Key = %q but no migration seeds a system_settings row under it", key)
	}
}

// keyFromConstant reads the Key constant out of this package's own source, so
// the census cannot be satisfied by a constant that has drifted from the
// literal the test would otherwise hardcode.
func keyFromConstant(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "internal", "common", "syssettings", "syssettings.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var key string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "Key" || len(vs.Values) != 1 {
			return true
		}
		if lit, ok := vs.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil {
				key = v
			}
		}
		return false
	})
	if key == "" {
		t.Fatal("could not read syssettings.Key from its own source")
	}
	return key
}

// repositoryWrittenKeys collects the keys passed to the settings repository's
// PutRaw, which is the tree's one parameterised writer of system_settings.
func repositoryWrittenKeys(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, top := range []string{"internal", "cmd", "pkg"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "PutRaw" {
					return true
				}
				lit, ok := call.Args[1].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
					out[v] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	return out
}

// seededKeys folds the migration SQL for rows inserted into system_settings.
func seededKeys(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	dir := filepath.Join(root, "internal", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(b)
		for _, block := range splitInserts(src) {
			for _, m := range reValLit.FindAllStringSubmatch(block, -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

// splitInserts returns the text following each INSERT INTO system_settings, up
// to the next semicolon — the VALUES tuples of that statement and nothing else.
func splitInserts(src string) []string {
	var out []string
	locs := reInsert.FindAllStringIndex(src, -1)
	for _, loc := range locs {
		rest := src[loc[1]:]
		if i := strings.Index(rest, ";"); i >= 0 {
			rest = rest[:i]
		}
		out = append(out, rest)
	}
	return out
}

// walkGoSQL visits every string literal in every non-test Go file under the
// repository's own source directories.
//
// Literals from the AST, not lines from a grep: prose about SQL is not SQL.
// tools/tablewriters learned this the hard way — a comment quoting a deleted
// query was read as a live one — and the same trap applies here, since three
// of the comments this change wrote quote the very keys it removed.
func walkGoSQL(t *testing.T, root string, visit func(file, sql string)) {
	t.Helper()
	for _, top := range []string{"internal", "cmd", "pkg"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.Contains(path, string(filepath.Separator)+"migrations"+string(filepath.Separator)) {
				return nil // migrations create and seed; they are the writers
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				visit(rel, s)
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
