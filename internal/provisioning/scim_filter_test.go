package provisioning

import (
	"errors"
	"testing"
)

// TestParseSCIMFilter covers the pure parsing/translation layer: the supported
// `attr eq "value"` idiom maps to a parameterized predicate, unknown attributes
// and unsupported operators fail loud with errUnsupportedFilter, and an empty
// filter is a no-op (nil predicate, nil error).
func TestParseSCIMFilter(t *testing.T) {
	t.Run("empty filter is a no-op", func(t *testing.T) {
		for _, f := range []string{"", "   ", "\t"} {
			p, err := parseSCIMFilter(f, scimUserFilterAttrs)
			if err != nil || p != nil {
				t.Fatalf("parseSCIMFilter(%q): want (nil,nil), got (%v,%v)", f, p, err)
			}
		}
	})

	t.Run("userName eq is case-insensitive and parameterized", func(t *testing.T) {
		p, err := parseSCIMFilter(`userName eq "Alice@Example.com"`, scimUserFilterAttrs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p == nil || p.column != "username" || !p.caseInsensitive || p.value != "Alice@Example.com" {
			t.Fatalf("unexpected predicate: %+v", p)
		}
		if got, want := p.clause(4), " AND LOWER(username) = LOWER($4)"; got != want {
			t.Fatalf("clause: got %q want %q", got, want)
		}
	})

	t.Run("attribute name is case-insensitive per RFC 7644", func(t *testing.T) {
		p, err := parseSCIMFilter(`USERNAME EQ "bob"`, scimUserFilterAttrs)
		if err != nil || p == nil || p.column != "username" {
			t.Fatalf("case-insensitive attr/op: got (%+v,%v)", p, err)
		}
	})

	t.Run("emails.value maps to email column", func(t *testing.T) {
		p, err := parseSCIMFilter(`emails.value eq "x@y.z"`, scimUserFilterAttrs)
		if err != nil || p == nil || p.column != "email" {
			t.Fatalf("emails.value: got (%+v,%v)", p, err)
		}
	})

	t.Run("externalId compares exactly (case-sensitive)", func(t *testing.T) {
		p, err := parseSCIMFilter(`externalId eq "ABC-123"`, scimUserFilterAttrs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p == nil || p.column != "external_id" || p.caseInsensitive {
			t.Fatalf("externalId predicate: %+v", p)
		}
		if got, want := p.clause(2), " AND external_id = $2"; got != want {
			t.Fatalf("clause: got %q want %q", got, want)
		}
	})

	t.Run("group displayName maps to name", func(t *testing.T) {
		p, err := parseSCIMFilter(`displayName eq "Engineering"`, scimGroupFilterAttrs)
		if err != nil || p == nil || p.column != "name" || p.value != "Engineering" {
			t.Fatalf("displayName: got (%+v,%v)", p, err)
		}
	})

	t.Run("escaped quotes in value are unescaped", func(t *testing.T) {
		p, err := parseSCIMFilter(`userName eq "a\"b\\c"`, scimUserFilterAttrs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p == nil || p.value != `a"b\c` {
			t.Fatalf("unescape: got %q", p.value)
		}
	})

	t.Run("unsupported operator fails loud", func(t *testing.T) {
		for _, f := range []string{
			`userName co "ali"`,
			`userName sw "a"`,
			`userName pr`,
			`userName eq "a" and email eq "b"`,
		} {
			if _, err := parseSCIMFilter(f, scimUserFilterAttrs); !errors.Is(err, errUnsupportedFilter) {
				t.Fatalf("parseSCIMFilter(%q): want errUnsupportedFilter, got %v", f, err)
			}
		}
	})

	t.Run("unknown/unfilterable attribute fails loud", func(t *testing.T) {
		for _, f := range []string{
			`password eq "secret"`,
			`displayName eq "x"`, // not in the user attr set
		} {
			if _, err := parseSCIMFilter(f, scimUserFilterAttrs); !errors.Is(err, errUnsupportedFilter) {
				t.Fatalf("parseSCIMFilter(%q): want errUnsupportedFilter, got %v", f, err)
			}
		}
	})
}
