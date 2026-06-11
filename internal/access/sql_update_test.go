package access

import (
	"regexp"
	"strings"
	"testing"
)

// TestBuildUpdateClause_HappyPath verifies the builder returns parallel
// SET clauses + args with 1-indexed pgx placeholders, and that
// `set: false` fields are skipped without consuming a placeholder.
func TestBuildUpdateClause_HappyPath(t *testing.T) {
	allowed := map[string]struct{}{"classification": {}, "require_auth": {}}
	identRE := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

	fields := []sqlUpdateField{
		{col: "classification", val: "critical", set: true},
		{col: "require_auth", val: true, set: false}, // skipped
	}

	sets, args, err := buildUpdateClause(fields, allowed, identRE)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(sets) != 1 || sets[0] != "classification = $1" {
		t.Errorf("sets = %v", sets)
	}
	if len(args) != 1 || args[0] != "critical" {
		t.Errorf("args = %v", args)
	}
}

// TestBuildUpdateClause_RejectsColumnNotInAllowlist mirrors the OAuth
// package test — the helper exists to make the column allow-list the
// single source of truth, so an off-list column must fail loudly.
func TestBuildUpdateClause_RejectsColumnNotInAllowlist(t *testing.T) {
	allowed := map[string]struct{}{"classification": {}}
	identRE := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

	_, _, err := buildUpdateClause(
		[]sqlUpdateField{{col: "secret_admin_flag", val: true, set: true}},
		allowed, identRE,
	)
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Errorf("err = %v, want allow-list rejection", err)
	}
}

// TestBuildUpdateClause_RejectsColumnFailingIdentRE — even if a column
// IS in the allow-list, a non-identifier-shaped name must fail.
func TestBuildUpdateClause_RejectsColumnFailingIdentRE(t *testing.T) {
	bad := "classification; DROP TABLE users;--"
	allowed := map[string]struct{}{bad: {}}
	identRE := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

	_, _, err := buildUpdateClause(
		[]sqlUpdateField{{col: bad, val: "x", set: true}},
		allowed, identRE,
	)
	if err == nil || !strings.Contains(err.Error(), "identifier regex") {
		t.Errorf("err = %v, want identifier-regex rejection", err)
	}
}

// TestDiscoveredPathsUpdatableColumns_MatchesRegex pins down both
// layers of the guard on the discovered_paths update path: every
// allow-listed column also passes the identifier regex. A new column
// added with a weird character gets caught here.
func TestDiscoveredPathsUpdatableColumns_MatchesRegex(t *testing.T) {
	for col := range discoveredPathsUpdatableColumns {
		if !discoveredPathsColumnRE.MatchString(col) {
			t.Errorf("discoveredPathsUpdatableColumns contains %q which does not match discoveredPathsColumnRE", col)
		}
	}
}

// TestDerefBool covers the small nil-safe dereference helper used by
// the update builder above.
func TestDerefBool(t *testing.T) {
	if derefBool(nil) != false {
		t.Error("derefBool(nil) = true, want false")
	}
	tr, fl := true, false
	if derefBool(&tr) != true {
		t.Error("derefBool(&true) = false, want true")
	}
	if derefBool(&fl) != false {
		t.Error("derefBool(&false) = true, want false")
	}
}
