package oauth

import "testing"

// TestPolicyOnlyRaisesTheRequirement: a policy may add a challenge, never remove
// one, and with no policy rows the pre-existing rule is untouched — that is what
// makes shipping this a no-op until an admin creates a policy.
func TestPolicyOnlyRaisesTheRequirement(t *testing.T) {
	cases := []struct {
		name           string
		enabled        bool
		skip           bool
		riskRequires   bool
		totpEnabled    bool
		policyRequires bool
		want           bool
	}{
		{"no factors, policy requires", false, false, false, false, true, false},
		{"push only, no policy", true, false, false, false, false, false},
		{"push only, policy requires", true, false, false, false, true, true},
		{"totp always challenged", true, false, false, true, false, true},
		{"trusted browser still skips", true, true, false, true, true, false},
		{"risk requires", true, false, true, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := challengeRequired(tc.enabled, tc.skip, tc.riskRequires, tc.totpEnabled, tc.policyRequires)
			if got != tc.want {
				t.Errorf("challengeRequired = %v, want %v", got, tc.want)
			}
		})
	}
}
