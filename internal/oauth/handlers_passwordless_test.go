package oauth

import (
	"strings"
	"testing"
)

// TestIsValidSessionID locks down the input-validation gate that
// handlers_passwordless.go uses to keep arbitrary strings out of Redis
// keys. The accept set is:
//   - a 36-character UUID (identity sessions, MFA challenge IDs), OR
//   - a 32..128-character base64url token ([A-Za-z0-9_-], which is what
//     GenerateRandomToken produces for /oauth/authorize login_session).
//
// Anything else (Redis key separators, path traversal, control chars,
// wildcards) must be rejected.
func TestIsValidSessionID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// --- UUID happy paths
		{"canonical lowercase UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"zero UUID", "00000000-0000-0000-0000-000000000000", true},
		{"valid UUID with mixed digits/letters", "abcdef01-2345-6789-abcd-ef0123456789", true},

		// --- base64url happy paths
		// 43 chars is what GenerateRandomToken(32) produces (32 random
		// bytes → 43 base64url chars without padding).
		{"43-char base64url with letters+digits", "dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXkpQ", true},
		{"43-char base64url with underscores", "Abc__def__ghi__jkl__mno__pqr__stu__vwx__yz0", true},
		{"43-char base64url with dashes", "Abc--def--ghi--jkl--mno--pqr--stu--vwx--yz0", true},
		{"32 chars (lower bound)", strings.Repeat("a", 32), true},
		{"128 chars (upper bound)", strings.Repeat("a", 128), true},
		// Uppercase is fine in base64url, so a UUID-shaped value with
		// uppercase letters is accepted via the token branch even though
		// the UUID regex is lowercase-only.
		{"uppercase UUID-shape accepted as token", "550E8400-E29B-41D4-A716-446655440000", true},

		// --- length checks
		{"empty string", "", false},
		{"31 chars (one short of token min)", strings.Repeat("a", 31), false},
		{"129 chars (one past token max)", strings.Repeat("a", 129), false},

		// --- injection-shaped inputs the validator MUST still reject
		{"path traversal with /", "../../../etc/passwd--invalid-shape-x", false},
		{"redis key separator injection", "550e8400-e29b-41d4-a716:malicious", false},
		{"newline injection", "550e8400-e29b-41d4-a716\n44665544000a", false},
		{"sql-injection-shaped string", "' OR 1=1 --                          ", false},
		{"wildcard glob", "550e8400-e29b-41d4-a716-44665544000*", false},
		{"contains a space", "550e8400 e29b 41d4 a716 446655440000xx", false},
		{"contains plus (base64 std, not URL-safe)", strings.Repeat("a", 31) + "+", false},
		{"contains slash (base64 std, not URL-safe)", strings.Repeat("a", 31) + "/", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidSessionID(tc.in); got != tc.want {
				t.Errorf("isValidSessionID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
