package oauth

import "testing"

func TestLoginIdentifierKind(t *testing.T) {
	for typed, want := range map[string]string{
		"mehmet.gungor":               "username",
		"mehmet.gungor.t@example.org": "email",
		" Someone@Example.ORG ":       "email",
		"DOMAIN\\sam":                 "username",
		"":                            "username",
	} {
		if got := loginIdentifierKind(typed); got != want {
			t.Errorf("loginIdentifierKind(%q) = %q, want %q", typed, got, want)
		}
	}
}
