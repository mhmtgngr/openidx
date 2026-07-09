package middleware

import "testing"

// TestInferResourceType locks in the path→OPA-resource mapping (and its plural
// stripping), since a wrong resource type feeds a wrong authorization decision.
func TestInferResourceType(t *testing.T) {
	cases := map[string]string{
		"/api/v1/identity/users":      "user",    // trailing s
		"/api/v1/identity/sessions":   "session", // trailing s
		"/api/v1/governance/policies": "policy",  // ies → y
		"/api/v1/x/statuses":          "status",  // ses → s
		"/api/v1/x/addresses":         "address", // ses → s
		"/api/v1/audit/audit":         "audit",   // no plural
		"/health":                     "",        // too short (<3 segments)
		"/api/v1":                     "",        // too short
		"":                            "",        // empty
	}
	for path, want := range cases {
		if got := inferResourceType(path); got != want {
			t.Errorf("inferResourceType(%q) = %q, want %q", path, got, want)
		}
	}
}
