package access

import "testing"

// TestDialIdentityRolesForRoute is the heart of enforcement: while the flag is
// off the blanket grant stays and the per-app grant is added beside it; once on,
// an app-backed service is dialable ONLY by identities carrying its marker.
func TestDialIdentityRolesForRoute(t *testing.T) {
	const appID = "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		name      string
		appID     string
		enforce   bool
		blanket   string
		wantRoles []string
	}{
		{"unlinked route keeps the blanket grant", "", false, "#access-proxy-clients", []string{"#access-proxy-clients"}},
		{"unlinked route keeps it under enforcement too", "", true, "#access-proxy-clients", []string{"#access-proxy-clients"}},
		{"app-backed route in report mode keeps both", appID, false, "#browzer-users", []string{"#browzer-users", "#app-" + appID}},
		{"app-backed route under enforcement drops the blanket grant", appID, true, "#browzer-users", []string{"#app-" + appID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dialIdentityRoles(tc.blanket, tc.appID, tc.enforce)
			if len(got) != len(tc.wantRoles) {
				t.Fatalf("roles = %v, want %v", got, tc.wantRoles)
			}
			for i := range got {
				if got[i] != tc.wantRoles[i] {
					t.Fatalf("roles = %v, want %v", got, tc.wantRoles)
				}
			}
		})
	}
}
