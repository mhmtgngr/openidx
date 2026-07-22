package oauth

import "testing"

func TestScopesCovered(t *testing.T) {
	tests := []struct {
		name      string
		granted   string
		requested string
		want      bool
	}{
		{"exact match", "openid profile", "openid profile", true},
		{"subset requested", "openid profile email", "openid", true},
		{"empty requested", "openid", "", true},
		{"missing scope", "openid", "openid email", false},
		{"empty granted, nonempty requested", "", "openid", false},
		{"both empty", "", "", true},
		{"order independent", "email openid profile", "profile openid", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopesCovered(tt.granted, tt.requested); got != tt.want {
				t.Errorf("scopesCovered(%q, %q) = %v, want %v", tt.granted, tt.requested, got, tt.want)
			}
		})
	}
}

func TestMergeScopes(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want string
	}{
		{"disjoint", "openid", "email", "openid email"},
		{"overlap deduped", "openid profile", "profile email", "openid profile email"},
		{"empty a", "", "openid", "openid"},
		{"empty b", "openid", "", "openid"},
		{"both empty", "", "", ""},
		{"identical", "openid profile", "openid profile", "openid profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeScopes(tt.a, tt.b); got != tt.want {
				t.Errorf("mergeScopes(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
