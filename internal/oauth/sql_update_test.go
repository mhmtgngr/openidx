package oauth

import (
	"regexp"
	"strings"
	"testing"
)

// TestBuildUpdateClause_HappyPath verifies the builder returns parallel
// SET clauses + args with 1-indexed pgx placeholders, and that
// `set: false` fields are skipped without consuming a placeholder.
func TestBuildUpdateClause_HappyPath(t *testing.T) {
	allowed := map[string]struct{}{"name": {}, "enabled": {}, "scope": {}}
	identRE := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

	fields := []sqlUpdateField{
		{col: "name", val: "alice", set: true},
		{col: "scope", val: "openid", set: false}, // skipped
		{col: "enabled", val: true, set: true},
	}

	sets, args, err := buildUpdateClause(fields, allowed, identRE)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{"name = $1", "enabled = $2"}
	if strings.Join(sets, ",") != strings.Join(want, ",") {
		t.Errorf("sets = %v, want %v", sets, want)
	}
	if len(args) != 2 || args[0] != "alice" || args[1] != true {
		t.Errorf("args = %v, want [alice true]", args)
	}
}

// TestBuildUpdateClause_AllSkipped — every field has set == false.
// The builder must return empty slices and no error so the caller can
// short-circuit on "nothing to update".
func TestBuildUpdateClause_AllSkipped(t *testing.T) {
	allowed := map[string]struct{}{"name": {}}
	identRE := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

	sets, args, err := buildUpdateClause(
		[]sqlUpdateField{{col: "name", val: "x", set: false}},
		allowed, identRE,
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(sets) != 0 || len(args) != 0 {
		t.Errorf("expected empty sets/args, got sets=%v args=%v", sets, args)
	}
}

// TestBuildUpdateClause_RejectsColumnNotInAllowlist is the main defense
// the helper exists for. A column that slips past the if-block
// scaffolding (refactor mistake, copy-paste from elsewhere, etc.) must
// fail loudly rather than being silently spliced into the SQL.
func TestBuildUpdateClause_RejectsColumnNotInAllowlist(t *testing.T) {
	allowed := map[string]struct{}{"name": {}}
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
// IS in the allow-list, a non-identifier-shaped name (e.g. from a
// careless map seed) must still be rejected by the regex.
func TestBuildUpdateClause_RejectsColumnFailingIdentRE(t *testing.T) {
	bad := "name; DROP TABLE users;--"
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

// TestSAMLSPUpdatableColumns_MatchesRegex pins down both layers of the
// guard on the SAML SP update path: every column the codepath might
// touch is in the allow-list map (covered implicitly by the file
// compiling), AND each name in that allow-list passes the
// identifier regex used at runtime. If a future maintainer adds a
// column with a weird character, this test catches it.
func TestSAMLSPUpdatableColumns_MatchesRegex(t *testing.T) {
	for col := range samlSPUpdatableColumns {
		if !samlSPColumnRE.MatchString(col) {
			t.Errorf("samlSPUpdatableColumns contains %q which does not match samlSPColumnRE", col)
		}
	}
}
