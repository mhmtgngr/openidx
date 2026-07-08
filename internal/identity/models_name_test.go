package identity

import "testing"

func strPtr(s string) *string { return &s }

// TestGetFormattedName covers the single-component name case that previously read parts[1]
// out of bounds, plus the other name-resolution branches.
func TestGetFormattedName(t *testing.T) {
	cases := []struct {
		name string
		user User
		want string
	}{
		{
			name: "given name only (regression: no OOB)",
			user: User{Name: &Name{GivenName: strPtr("Ada")}},
			want: "Ada",
		},
		{
			name: "family name only",
			user: User{Name: &Name{FamilyName: strPtr("Lovelace")}},
			want: "Lovelace",
		},
		{
			name: "given and family",
			user: User{Name: &Name{GivenName: strPtr("Ada"), FamilyName: strPtr("Lovelace")}},
			want: "Ada Lovelace",
		},
		{
			name: "formatted takes precedence",
			user: User{Name: &Name{Formatted: strPtr("Dr. Ada Lovelace"), GivenName: strPtr("Ada")}},
			want: "Dr. Ada Lovelace",
		},
		{
			name: "falls back to display name",
			user: User{DisplayName: strPtr("ada_l")},
			want: "ada_l",
		},
		{
			name: "falls back to username",
			user: User{UserName: "ada@example.com"},
			want: "ada@example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.GetFormattedName(); got != tc.want {
				t.Errorf("GetFormattedName() = %q, want %q", got, tc.want)
			}
		})
	}
}
