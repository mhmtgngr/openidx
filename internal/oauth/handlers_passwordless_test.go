package oauth

import "testing"

// TestIsValidSessionID locks down the input-validation gate that
// handlers_passwordless.go uses to keep arbitrary strings out of Redis keys.
// The accept set is "strict UUID v4-shape, 36 characters, lowercase hex" —
// any drift (length, casing, character class, embedded separators) opens a
// key-injection / path-traversal vector, so we pin all those edges here.
func TestIsValidSessionID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// --- happy path
		{"canonical lowercase UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"another valid UUID", "00000000-0000-0000-0000-000000000000", true},
		{"valid UUID with mixed digits/letters", "abcdef01-2345-6789-abcd-ef0123456789", true},

		// --- length checks
		{"empty string", "", false},
		{"35 chars (one short)", "550e8400-e29b-41d4-a716-44665544000", false},
		{"37 chars (one too long)", "550e8400-e29b-41d4-a716-4466554400000", false},

		// --- format checks
		{"missing dashes", "550e8400e29b41d4a716446655440000bad0", false},
		{"dashes in wrong positions", "550e84-00e29b-41d4a716-446655440000-z", false},
		{"uppercase rejected", "550E8400-E29B-41D4-A716-446655440000", false},
		{"non-hex char in UUID slot", "550e8400-e29b-41d4-a716-44665544000g", false},

		// --- injection-shaped inputs the regex must reject
		{"path traversal attempt", "../../../etc/passwd--invalid-shape-x", false},
		{"redis key separator injection", "550e8400-e29b-41d4-a716:malicious", false},
		{"newline injection", "550e8400-e29b-41d4-a716\n44665544000a", false},
		{"sql-injection-shaped string", "' OR 1=1 --                          ", false},
		{"wildcard glob", "550e8400-e29b-41d4-a716-44665544000*", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidSessionID(tc.in); got != tc.want {
				t.Errorf("isValidSessionID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
