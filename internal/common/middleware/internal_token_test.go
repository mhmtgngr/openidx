package middleware

import "testing"

// The internal service token is the only credential POST /api/v1/audit/events
// takes. Unset, it must admit nobody -- not the caller who sends nothing, and
// not the one who sends an empty header -- and set, only its exact value.
func TestTheInternalServiceTokenAdmitsOnlyItsExactValue(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		name                  string
		presented, configured string
		want                  bool
	}{
		{"the configured token", token, token, true},
		{"no token presented", "", token, false},
		{"another token", "fedcba9876543210fedcba9876543210", token, false},
		{"a prefix of the token", token[:16], token, false},
		{"the token and more", token + "x", token, false},
		{"unconfigured, nothing presented", "", "", false},
		{"unconfigured, something presented", "anything", "", false},
	} {
		if got := ValidInternalToken(c.presented, c.configured); got != c.want {
			t.Errorf("%s: ValidInternalToken = %v, want %v", c.name, got, c.want)
		}
	}
}
