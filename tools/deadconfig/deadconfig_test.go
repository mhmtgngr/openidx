package main

import (
	"go/token"
	"sort"
	"strings"
	"testing"
)

// The finding rule is one line, so it is tested against synthetic input first:
// no load, no type checking, no fixtures. TestTheFixtureIsRead below runs the
// real analysis over testdata, and TestTheRegisterMatchesTheTree runs it over
// the module.

func TestTheFindingRule(t *testing.T) {
	declared := []field{
		{Key: "pkg.C.Live", Tag: "live", Full: "live", Decl: token.Pos(10)},
		{Key: "pkg.C.Dead", Tag: "dead", Full: "dead", Decl: token.Pos(20)},
	}

	t.Run("a field something reads is not a finding", func(t *testing.T) {
		got := report(declared, map[token.Pos]bool{token.Pos(10): true, token.Pos(20): true})
		if len(got) != 0 {
			t.Fatalf("got %v, want none", keys(got))
		}
	})

	t.Run("a field nothing reads is a finding", func(t *testing.T) {
		got := report(declared, map[token.Pos]bool{token.Pos(10): true})
		if len(got) != 1 || got[0].Key != "pkg.C.Dead" {
			t.Fatalf("got %v, want [pkg.C.Dead]", keys(got))
		}
	})

	t.Run("identity is the declaration position, not the name", func(t *testing.T) {
		// Two structs with a field of the same name, one live and one dead:
		// `Enabled` is a field on six config structs in this tree, and a
		// name-keyed census would let SMSConfig.Enabled clear
		// PushMFAConfig.Enabled. That is not a hypothetical -- the first pass of
		// this census, done with ripgrep, reported exactly one finding where
		// there were six.
		pair := []field{
			{Key: "pkg.A.Enabled", Tag: "enabled", Full: "a.enabled", Decl: token.Pos(30)},
			{Key: "pkg.B.Enabled", Tag: "enabled", Full: "b.enabled", Decl: token.Pos(40)},
		}
		got := report(pair, map[token.Pos]bool{token.Pos(30): true})
		if len(got) != 1 || got[0].Key != "pkg.B.Enabled" {
			t.Fatalf("got %v, want [pkg.B.Enabled]", keys(got))
		}
	})
}

// The analysis proper, over a fixture whose answer is known: two of four
// settable fields are read, and the two that are not include one a test touches.
func TestTheFixtureIsRead(t *testing.T) {
	declared, read, err := analyze([]string{"./testdata/configfixture"})
	if err != nil {
		t.Fatalf("analyze the fixture: %v", err)
	}

	wantDeclared := []string{
		"configfixture.Fixture.Nested",
		"configfixture.Fixture.Read",
		"configfixture.Fixture.Unread",
		"configfixture.Section.Deep",
		"configfixture.Section.DeepUnread",
	}
	var gotDeclared []string
	for _, f := range declared {
		gotDeclared = append(gotDeclared, f.Key)
	}
	sort.Strings(gotDeclared)
	if strings.Join(gotDeclared, ",") != strings.Join(wantDeclared, ",") {
		t.Fatalf("declared = %v, want %v (NotBound carries no mapstructure tag and must not appear)", gotDeclared, wantDeclared)
	}

	full := map[string]string{}
	for _, f := range declared {
		full[f.Key] = f.Full
	}
	if got := full["configfixture.Section.Deep"]; got != "section.deep" {
		t.Errorf("nested key = %q, want %q: a leaf reported alone names a setting several structs share", got, "section.deep")
	}
	if got := full["configfixture.Fixture.Read"]; got != "read" {
		t.Errorf("root key = %q, want %q", got, "read")
	}

	got := keys(report(declared, read))
	sort.Strings(got)
	want := []string{"configfixture.Fixture.Unread", "configfixture.Section.DeepUnread"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings = %v, want %v. Fixture.Unread is touched only by fixture_test.go, "+
			"and a test is not a reader: that is exactly the shape ENABLE_MFA had.", got, want)
	}
}

// The gate's contract with the tree: every finding is registered and every
// register entry still reproduces. Slow -- it type-checks the module -- so it is
// the half that -short skips, like tools/deadservice.
func TestTheRegisterMatchesTheTree(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the whole module")
	}
	declared, read, err := analyze([]string{"../../..."})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(declared) == 0 {
		t.Fatal("no mapstructure-tagged fields found; the load found nothing and every check below would pass vacuously")
	}

	findings := map[string]bool{}
	for _, f := range report(declared, read) {
		findings[f.Key] = true
		if _, ok := knownUnread[f.Key]; !ok {
			t.Errorf("%s: an operator can set %q and nothing in the product reads it. "+
				"Give it a reader, or retire it in internal/common/config/retired.go so an operator "+
				"who sets it is told at startup that it does nothing.", f.Key, f.Full)
		}
	}
	for key := range knownUnread {
		if !findings[key] {
			t.Errorf("%s is registered as unread and something reads it now; delete its line in known.go", key)
		}
	}
}

// The mirror census, over the real tree: no settings table in the documentation
// may name an environment variable nothing binds. This is the direction an
// operator meets first — they read the page, set what it offers, and nothing
// happens — and the page carried 63 such rows, including the four OAUTH_*_TTL,
// the five PASSWORD_* and one misspelled MFA_WEBARUTHN_ENABLED, which is the
// clearest evidence that nobody had ever tried it.
func TestNoDocumentedSettingIsBoundByNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the whole module")
	}
	declared, _, err := analyze([]string{"../../..."})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	root = "../.."
	t.Cleanup(func() { root = "." })
	phantom, err := documentedButUnbound(declared)
	if err != nil {
		t.Fatalf("documentedButUnbound: %v", err)
	}
	if documentedCount == 0 {
		t.Fatal("no documented settings found; the scan read no settings tables and would pass vacuously")
	}
	for _, p := range phantom {
		t.Errorf("%s:%d documents %s and nothing in the product binds it: %s",
			p.File, p.Line, p.Name, strings.TrimSpace(p.Row))
	}
}

// The register of variables that belong to something else must stay small and
// must stay explained: an entry with no reason is a name someone waved through.
func TestEveryExternalVariableSaysWhoseItIs(t *testing.T) {
	for name, reason := range knownExternal {
		if len(reason) < 40 {
			t.Errorf("knownExternal[%q] = %q — too short to say whose variable it is", name, reason)
		}
	}
}

func keys(fs []field) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}
