package admin

import "testing"

func TestValidateMFAConditions(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"factor_enrolled", `{"factor_enrolled":true}`, false},
		{"min_risk_score", `{"min_risk_score":70}`, false},
		{"client_ids", `{"client_ids":["admin-console"]}`, false},
		{"combined", `{"factor_enrolled":true,"client_ids":["a"]}`, false},
		{"empty", `{}`, false},
		// Silently ignoring unknown keys is how this table became decorative:
		// an admin authors a policy, nothing reads the key, nothing happens.
		{"unknown key rejected", `{"require_hardware_token":true}`, true},
		{"wrong type rejected", `{"factor_enrolled":"yes"}`, true},
		{"min_risk_score wrong type rejected", `{"min_risk_score":"high"}`, true},
		{"client_ids not an array rejected", `{"client_ids":"admin-console"}`, true},
		{"client_ids non-string element rejected", `{"client_ids":["admin-console", 42]}`, true},
		{"not an object", `[1,2,3]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMFAConditions([]byte(tc.in))
			if (err != nil) != tc.wantErr {
				t.Errorf("validateMFAConditions(%s) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}
